//      cursord.c
//      
//      Copyright 2012 Ni <_ni_@mail.ru>
//      

#ifdef __GNUC__
#define _GNU_SOURCE /* для strsignal() */
#endif

#define NO_FCGI_DEFINES

#include "fcgi_stdio.h"
#include "hiredis/hiredis.h"

#include <stdlib.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>

#define PROG_NAME "cursord"
#define LOCK_FILE_PATH "/var/run/cursord.pid"
#define LIB_PROC_NAME "run"
#define AMOUNT_CHILD 4

/*#define _FATAL_ERROR(...) \
{\
printf("ERR: %s (%d):", __FUNCTION__, __LINE__);\
printf(__VA_ARGS__);\
printf("\n");\
exit(1);\
}*/

#define _FATAL_ERROR(S,...) \
{\
syslog(LOG_LOCAL0|LOG_INFO,"ERR: %s (%d): "S, __FUNCTION__, __LINE__, ## __VA_ARGS__);\
cur_exit(1);\
}

const char *const	pLockFilePath	= LOCK_FILE_PATH;
const char *const	pLibName		= "/home/ni/проекты/libMarket/libMarket.so";
int					lockFD			= -1;
int					listen_socket	= -1;
void				*dl_handle		= 0;
int(*lib_func)(FCGX_Request*);
volatile sig_atomic_t	now_child	= 0;
volatile sig_atomic_t	lock_FCGI	= 0;
volatile sig_atomic_t	TotalShutdown	= 0;
volatile sig_atomic_t	gCaughtHupSignal	= 0;

//Процедура выхода
int cur_exit(int state)
{
	if(lockFD!=-1)
		{
		close(lockFD);
		unlink(pLockFilePath);
		lockFD=-1;
		}

	if(listen_socket!=-1)
		{
		close(listen_socket);
		listen_socket=-1;
		}
		
	if(dl_handle!=0)
		{
		dlclose(dl_handle);
		dl_handle=0;
		}
	syslog(LOG_NOTICE, "Program is closed%s }",((state)?(" with an error."):(".")));
	closelog();
	exit(state);
}

void FatalSigHandler(int sig)
{
#ifdef _GNU_SOURCE
	syslog(LOG_LOCAL0|LOG_INFO,"caught signal: %s - exiting",strsignal(sig));
#else
	syslog(LOG_LOCAL0|LOG_INFO,"caught signal: %d - exiting",sig);
#endif

	cur_exit(0);
}

void TermHandler(int sig)
{
	cur_exit(0);
}

void Usr1Handler(int sig)
{
	syslog(LOG_LOCAL0|LOG_INFO,"caught SIGUSR1 - soft shutdown");
	TotalShutdown=1;  //надо корректно завершить все процессы

	return;
}

void HupHandler(int sig)
{
	//syslog(LOG_LOCAL0|LOG_INFO,"caught SIGHUP");
	gCaughtHupSignal=1;
	TotalShutdown=1;  //надо корректно завершить все процессы

	/****************************************************************/
	/* perhaps at this point you would re-read a configuration file */
	/****************************************************************/

	return;
}

int ConfigureSignalHandlers(void)
{
	struct sigaction		sighupSA,sigusr1SA,sigtermSA;

	/* ignore several signals because they do not concern us. In a
		production server, SIGPIPE would have to be handled as this
		is raised when attempting to write to a socket that has
		been closed or has gone away (for example if the client has
		crashed). SIGURG is used to handle out-of-band data. SIGIO
		is used to handle asynchronous I/O. SIGCHLD is very important
		if the server has forked any child processes. */

	signal(SIGUSR2, SIG_IGN);	
	signal(SIGPIPE, SIG_IGN);
	signal(SIGALRM, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTTOU, SIG_IGN);
	signal(SIGURG, SIG_IGN);
	signal(SIGXCPU, SIG_IGN);
	signal(SIGXFSZ, SIG_IGN);
	signal(SIGVTALRM, SIG_IGN);
	signal(SIGPROF, SIG_IGN);
	signal(SIGIO, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	/* these signals mainly indicate fault conditions and should be logged.
		Note we catch SIGCONT, which is used for a type of job control that
		is usually inapplicable to a daemon process. We don't do anyting to
		SIGSTOP since this signal can't be caught or ignored. SIGEMT is not
		supported under Linux as of kernel v2.4 */

	signal(SIGQUIT, FatalSigHandler);
	signal(SIGILL, FatalSigHandler);
	signal(SIGTRAP, FatalSigHandler);
	signal(SIGABRT, FatalSigHandler);
	signal(SIGIOT, FatalSigHandler);
	signal(SIGBUS, FatalSigHandler);
#ifdef SIGEMT /* this is not defined under Linux */
	signal(SIGEMT,FatalSigHandler);
#endif
	signal(SIGFPE, FatalSigHandler);
	signal(SIGSEGV, FatalSigHandler);
	signal(SIGSTKFLT, FatalSigHandler);
	signal(SIGCONT, FatalSigHandler);
	signal(SIGPWR, FatalSigHandler);
	signal(SIGSYS, FatalSigHandler);
	
	/* these handlers are important for control of the daemon process */

	/* TERM  - shut down immediately */
	
	sigtermSA.sa_handler=TermHandler;
	sigemptyset(&sigtermSA.sa_mask);
	sigtermSA.sa_flags=0;
	sigaction(SIGTERM,&sigtermSA,NULL);
		
	/* USR1 - finish serving the current connection and then close down
		(graceful shutdown) */
	
	sigusr1SA.sa_handler=Usr1Handler;
	sigemptyset(&sigusr1SA.sa_mask);
	sigusr1SA.sa_flags=0;
	sigaction(SIGUSR1,&sigusr1SA,NULL);
	
	/* HUP - finish serving the current connection and then restart
		connection handling. This could be used to force a re-read of
		a configuration file for example */
	
	sighupSA.sa_handler=HupHandler;
	sigemptyset(&sighupSA.sa_mask);
	sighupSA.sa_flags=0;
	sigaction(SIGHUP,&sighupSA,NULL);
	
	return 0;
}

//Процедура подключения динамической библиотеки
int cur_dlib()
{
	char *error;
	
	//Проверим - возможно библиотека открыта
	if(dl_handle!=0){
		dlclose(dl_handle);
		dl_handle=0;
	}
	//Открываем совместно используемую библиотеку
	dl_handle = dlopen( pLibName, RTLD_LAZY );
	if (!dl_handle) _FATAL_ERROR("open lib failed. %s",dlerror());

	//Находим адрес функции в библиотеке
	lib_func = (int (*)(FCGX_Request*))dlsym( dl_handle, LIB_PROC_NAME );
	error = dlerror();
	if (error != NULL) _FATAL_ERROR("init proclib failed. %s",error);

    return 0;
}

//Процедура демонизации
int cur_daemon()
{
	int				fd,i;
	struct flock	exclusiveLock;
	char			pid_buf[17];

	chdir("/");
	
	//создадим pid-файл и заблокируем его
	if((lockFD=open(pLockFilePath,O_RDWR|O_CREAT|O_EXCL,0644))<0) {
		_FATAL_ERROR("create lock file failed");
	}
	exclusiveLock.l_type=F_WRLCK;
	exclusiveLock.l_whence=SEEK_SET;
	exclusiveLock.l_len=exclusiveLock.l_start=0;
	exclusiveLock.l_pid=0;
	if(fcntl(lockFD,F_SETLK,&exclusiveLock)<0)_FATAL_ERROR("Can't get lockfile");

	switch (fork()) {
		case -1:
			_FATAL_ERROR("fork() failed");
		case 0:
			break;
		default:
			exit(0);
	}

	if (setsid() == -1)	_FATAL_ERROR("setsid() failed");
	
	//продолжим блокировку с pid-файлом, запишем в него индетификатор процесса
	if(ftruncate(lockFD,0)<0)
		return -1;
	sprintf(pid_buf,"%d\n",(int)getpid());
	write(lockFD,pid_buf,strlen(pid_buf));

	//закроем открытые файловые дескрипторы, кроме lockFD
	fd = sysconf(_SC_OPEN_MAX);
	for(i=fd-1;i>=0;--i)
		if(i!=lockFD) close(i);
		
	umask(0);
	
	if ((fd = open("/dev/null", O_RDWR, 0)) == -1) _FATAL_ERROR("open(\"/dev/null\") failed");
	if (dup2(fd, STDIN_FILENO) == -1) _FATAL_ERROR("dup2(STDIN) failed");
	if (dup2(fd, STDOUT_FILENO) == -1) _FATAL_ERROR("dup2(STDOUT) failed");
	if (dup2(fd, STDERR_FILENO) == -1) _FATAL_ERROR("dup2(STDERR) failed");
	if (fd > STDERR_FILENO)
		if (close(fd) == -1) _FATAL_ERROR("close() failed");

	setpgrp();
 
	return 0;
}

static void *WorkProc(void* a)
{
	static pthread_mutex_t accept_mutex = PTHREAD_MUTEX_INITIALIZER;
	FCGX_Request request;
	int rc;//,i=0;
	//syslog(LOG_NOTICE, "        pthread start");
	if(FCGX_InitRequest(&request,  listen_socket, 0))_FATAL_ERROR("Request FCGI is not initialized");
	/*	
	//подключаемся к БД
	redisContext *c;
    //redisReply *reply;
    c = redisConnect((char*)"127.0.0.2", 6379);
    if (c->err) _FATAL_ERROR("Connection error: %s\n", c->errstr);
    */
	//обрабатываем запросы
	while(!TotalShutdown){
		/*if(lock_FCGI) continue;
		lock_FCGI = 1;
		if(FCGX_Accept_r(&request) < 0){
			lock_FCGI = 0;
			break;
		}
		lock_FCGI = 0;*/
		
		pthread_mutex_lock(&accept_mutex);
		rc = FCGX_Accept_r(&request);
        pthread_mutex_unlock(&accept_mutex);
		if (rc < 0){
			syslog(LOG_NOTICE, "        Can not accept new request.  err=%i",rc);
			continue;
		}
		
		//FCGX_FPrintF(request.out, "Set-Cookie: c1=123\r\n"
        //"Content-type: text/html; charset=utf-8\r\n\r\n"
        //"<TITLE>fastcgi</TITLE>"
        //"<script type=\"text/javascript\">document.cookie = \"temperature=20\"</script>"
        //"<html><body><H1>УРА!!! :))) </H1><p>%i</p><p>i=%i</p><p>thread_id=%i</p></body></html>",(int)getpid(),i++,(int)a);
        lib_func(&request);
        
		FCGX_Finish_r(&request);
		//if((TotalShutdown==1)&&(gCaughtHupSignal==0))break;	
	};
	//syslog(LOG_NOTICE, "        pthread close");
	return 0;
}

int cur_createThreads()
{
	int pid;
	
	//создаём потоки
	pthread_t id[AMOUNT_CHILD];
	for (pid = 0; pid < AMOUNT_CHILD; pid++)
        pthread_create(&id[pid], 0, WorkProc,(void*)pid);
		
	//ждём завершения потоков (надо эту хрень сделать гибже)
	
	for (pid = 0; pid < AMOUNT_CHILD; pid++) 
        pthread_join(id[pid], 0);
    return 0;
}

int main(int argc, char **argv)
{
	int pid;
	
	//Включим логирование
	openlog(PROG_NAME,LOG_PID|LOG_CONS|LOG_NDELAY|LOG_NOWAIT,LOG_LOCAL0);
	setlogmask(LOG_UPTO(LOG_DEBUG));

	if (argc > 1)
	{
		int fd;
 		char pid_buf[16];

		syslog(LOG_NOTICE, "{ Program [%s %s] started by User %d", argv[0], argv[1], getuid ());

		//Определим pid запущенного процесса
		if ((fd = open(pLockFilePath, O_RDONLY)) < 0) _FATAL_ERROR("%s is not running.",PROG_NAME);
		pid = read(fd, pid_buf, 16);
		close(fd);
		pid_buf[pid] = 0;
		pid = atoi(pid_buf);
		if(!strcmp(argv[1], "stop"))
		{
			kill(pid, SIGUSR1);
			cur_exit(0);
		}
		if(!strcmp(argv[1], "restart"))
		{
			kill(pid, SIGHUP);
			cur_exit(0);
		}
		printf("usage %s [stop|restart]\n", argv[0]);
		_FATAL_ERROR("Invalid arguments");
	} else syslog(LOG_NOTICE, "{ Program [%s] started by User %d", argv[0], getuid ());

	//демонизируем процесс
    if(cur_daemon()<0) _FATAL_ERROR("Failed to become daemon process");
   
    //обрабатываем сигалы
    if(ConfigureSignalHandlers()<0)
    {
		syslog(LOG_LOCAL0|LOG_INFO,"ConfigureSignalHandlers failed, errno=%d",errno);
		_FATAL_ERROR("Failed to become daemon process");
	}
	
	//начинаем слушать порт
	const char *port=":2205";
	int listenQueueBacklog = 400;
	if(FCGX_Init())_FATAL_ERROR("FCGI is not initialized");
	if((listen_socket = FCGX_OpenSocket(port, listenQueueBacklog))< 0)_FATAL_ERROR("Socket is not open");

    /*//создаём дочерние процессы и следим за ними
    while(!TotalShutdown) {
		if(now_child<AMOUNT_CHILD){
			switch (fork()==pid) {
				case -1:
					_FATAL_ERROR("fork() child failed");
				case 0:
					syslog(LOG_NOTICE, "        { Cild №%d [%s] started by User %d", now_child, argv[0], getuid());
					WorkProc();
					syslog(LOG_NOTICE, "        Cild is closed }");
					exit(0);
				default: now_child++;
					
			}
		}
	}*/
	
	do{
		gCaughtHupSignal=0;
		TotalShutdown=0;
		//инициализируем динамическую библиотеку
		if(cur_dlib()<0) _FATAL_ERROR("Failed to open dlib");
		//запускаем рабочие потоки
		if(cur_createThreads()<0) _FATAL_ERROR("Failed to create threads");
	}while(gCaughtHupSignal);
	 
    	
	cur_exit(0);
	return 0;
}

