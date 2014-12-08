#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include "message.h"
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>

static char active = 1;
static long connection_errors;
static int internal_stop_logging = 0;
static CRITICAL_SECTION cs;
static const char* nullString = "null";

static struct st_mysql_show_var audit_status[] = {	
	{"windows_audit_connection_errors", (char*) &connection_errors, SHOW_LONG},
	{0,0,0}
};

static void update_active(MYSQL_THD thd, struct st_mysql_sys_var *var, void *var_ptr, const void *save) {	
	char new_is_active = *(char*) save;
	if (new_is_active == active) return;
	EnterCriticalSection(&cs);
	internal_stop_logging = 1;
	active = new_is_active;	
	EventWriteActiveChanged("windows_audit_active", active);
	internal_stop_logging = 0;
	LeaveCriticalSection(&cs);
}

static MYSQL_SYSVAR_BOOL(active, active, PLUGIN_VAR_OPCMDARG, "Turn on/off the logging.", NULL, update_active, 1);

static struct st_mysql_sys_var* vars[] = {
	MYSQL_SYSVAR(active),
	NULL
};

static int windows_audit_plugin_init(void *arg)
{	
	if (EventRegisterMySQLWindowsAuditProvider() != ERROR_SUCCESS) {
		fwprintf(stderr, L"Can't register Windows log provider.\n");
		return -1;
	}
	InitializeCriticalSection(&cs);	
	connection_errors = 0;
	fwprintf(stderr, L"Windows Audit Plugin STARTED.\n");	
	return 0;
}

static int windows_audit_plugin_deinit(void *arg)
{	
	if (EventUnregisterMySQLWindowsAuditProvider() != ERROR_SUCCESS) {
		fwprintf(stderr, L"Can't unregister Windows log provider.\n");
		return -1;
	}
	DeleteCriticalSection(&cs);
	fwprintf(stderr, L"Windows Audit Plugin STOPPED.\n");
	return 0;
}

static const char* new_cstr(const char* str, ULONG size) {		
	char* result = (char*) malloc(sizeof(char) * ((size==0) ? sizeof(nullString) : size) + 1);
	memcpy(result, (size==0) ? nullString : str, ((size==0) ? sizeof(nullString) : size) + 1);	
	return result;
}

static void event_log(PCEVENT_DESCRIPTOR descriptor, EVENT_DATA_DESCRIPTOR* data, const struct mysql_event_connection* connEvent) {
	const char* user, *host, *ip, *database;
	EventDataDescCreate(&data[0], &(connEvent->status), sizeof(const signed int)  );

	user = new_cstr(connEvent->user, connEvent->user_length);												
	EventDataDescCreate(&data[1], user, strlen(user)+1);

	host = new_cstr(connEvent->host, connEvent->host_length);
	EventDataDescCreate(&data[2], host, strlen(host)+1);

	ip = new_cstr(connEvent->ip, connEvent->ip_length);
	EventDataDescCreate(&data[3], ip, strlen(ip)+1);

	database = new_cstr(connEvent->database, connEvent->database_length);															
	EventDataDescCreate(&data[4], database, strlen(database)+1);

	EventWrite(MySQLWindowsAuditProviderHandle, descriptor, 5, data);

	free((void*) user);
	free((void*) host);
	free((void*) ip);
	free((void*) database);
}

static void windows_audit_notify(MYSQL_THD thd, unsigned int event_class, const void *e)
{ 
	const struct mysql_event_connection *connEvent;	
	EVENT_DATA_DESCRIPTOR eventData[5];

	if (internal_stop_logging || !active) return;	
	EnterCriticalSection(&cs);	
	
	if (event_class == MYSQL_AUDIT_CONNECTION_CLASS) {
		internal_stop_logging = 1;	
		connEvent = (const struct mysql_event_connection *) e;

		if (connEvent->status > 0) {
			event_log(&Error, eventData, connEvent);
			connection_errors++;
		} else {
			switch (connEvent->event_subclass) {
				case MYSQL_AUDIT_CONNECTION_CONNECT:
					event_log(&Connect, eventData, connEvent);
					break;
				case MYSQL_AUDIT_CONNECTION_DISCONNECT:      
					EventWriteDisconnect(connEvent->status);
					break;
				case MYSQL_AUDIT_CONNECTION_CHANGE_USER:     
					event_log(&Change, eventData, connEvent);
					break;
				default:					
					break;			
			}
		}
		internal_stop_logging = 0;
	}
	
	LeaveCriticalSection(&cs);
}


/*
  Plugin type-specific descriptor
*/

static struct st_mysql_audit windows_audit_descriptor=
{
  MYSQL_AUDIT_INTERFACE_VERSION,                       /* interface version    */
  NULL,                                                /* release_thd function */
  windows_audit_notify,                                /* notify function      */
  { (unsigned long) MYSQL_AUDIT_CONNECTION_CLASSMASK } /* class mask           */
};

/*
  Plugin library descriptor
*/

mysql_declare_plugin(windows_audit)
{
  MYSQL_AUDIT_PLUGIN,						/* type                            */
  &windows_audit_descriptor,				/* descriptor                      */
  "WINDOWS_AUDIT",							/* name                            */
  "Jocki Hendry",		  					/* author                          */
  "Audit connections to Windows Log",		/* description                     */
  PLUGIN_LICENSE_GPL,
  windows_audit_plugin_init,				/* init function (when loaded)     */
  windows_audit_plugin_deinit,				/* deinit function (when unloaded) */
  0x0001,									/* version                         */
  audit_status,								/* status variables                */
  vars,										/* system variables                */
  NULL,
  0,
}
mysql_declare_plugin_end;