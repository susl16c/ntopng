/*
 *
 * (C) 2013-21 - ntop.org
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#include "ntop_includes.h"

typedef struct _activity_descr {
  const char *path;
  u_int32_t periodicity;
  u_int32_t max_duration_secs;
  ThreadPool *pool;
  bool align_to_localtime;  
  bool exclude_viewed_interfaces;
  bool exclude_pcap_dump_interfaces;
} activity_descr;

/* ******************************************* */

PeriodicActivities::PeriodicActivities() {
  for(u_int16_t i = 0; i < CONST_MAX_NUM_THREADED_ACTIVITIES; i++)
    activities[i] = NULL;

  second_thread_pool = minute_thread_pool = five_minute_thread_pool
    = hourly_thread_pool = daily_thread_pool
    = housekeeping_pool = NULL;

  num_activities = 0;
}

/* ******************************************* */

PeriodicActivities::~PeriodicActivities() {
  /* Important: destroy the ThreadedActivities only *after* ensuring that both its pthreadLoop
   * thread and the possibly running activity into the ThreadPool::run thread
   * have been terminated. */
  for(u_int16_t i = 0; i < CONST_MAX_NUM_THREADED_ACTIVITIES; i++) {
    /* This will terminate the pthreadLoop of the activities */
    if(activities[i])
      activities[i]->terminateEnqueueLoop();
  }

  /* This will terminate any possibly running activities into the ThreadPool::run */
  if(second_thread_pool)       delete second_thread_pool;
  if(minute_thread_pool)       delete minute_thread_pool;
  if(five_minute_thread_pool)  delete five_minute_thread_pool;
  if(hourly_thread_pool)       delete hourly_thread_pool;
  if(daily_thread_pool)        delete daily_thread_pool;
  if(housekeeping_pool)        delete housekeeping_pool;
  
  /* Now it's safe to delete the activities as no other thread is executing
   * their code. */
  for(u_int16_t i = 0; i < CONST_MAX_NUM_THREADED_ACTIVITIES; i++) {
    if(activities[i]) {
      delete activities[i];
      activities[i] = NULL;
      num_activities--;
    }
  }
}

/* ******************************************* */

void PeriodicActivities::lua(NetworkInterface *iface, lua_State *vm) {
  for(int i = 0; i < num_activities; i++) {
    if(activities[i])
      activities[i]->lua(iface, vm);
  }
}

/* ******************************************* */

void PeriodicActivities::sendShutdownSignal() {
  for(u_int16_t i = 0; i < CONST_MAX_NUM_THREADED_ACTIVITIES; i++) {
    if(activities[i])
      activities[i]->shutdown();
  }
}

/* ******************************************* */

void PeriodicActivities::startPeriodicActivitiesLoop() {
  struct stat buf;
  ThreadedActivity *startup_activity;
  
  ntop->getTrace()->traceEvent(TRACE_NORMAL, "Started periodic activities loop...");

  if(stat(ntop->get_callbacks_dir(), &buf) != 0) {
    ntop->getTrace()->traceEvent(TRACE_ERROR, "Unable to read directory %s", ntop->get_callbacks_dir());
    ntop->getTrace()->traceEvent(TRACE_ERROR, "Possible cause:\n");
    ntop->getTrace()->traceEvent(TRACE_ERROR, "The current user cannot access %s.", ntop->get_callbacks_dir());
    ntop->getTrace()->traceEvent(TRACE_ERROR, "Please fix the directory right or add --dont-change-user to");
    ntop->getTrace()->traceEvent(TRACE_ERROR, "the ntopng command line.");
    exit(0);
  }

  if((startup_activity = new (std::nothrow) ThreadedActivity(STARTUP_SCRIPT_PATH))) {
    /*
      Don't call run() as by the time the script will be run
      the delete below will free the memory 
    */
    startup_activity->runSystemScript(time(NULL));
    delete startup_activity;
    startup_activity = NULL;
  }

  static activity_descr ad[] = {
    // Script                  Periodicity (s) Max (s) Pool                       Align  !View  !PCAP
    { SECOND_SCRIPT_DIR,                    1,     65, second_thread_pool,        false, false, true  }, 
    { FIVE_SECOND_SCRIPT_DIR,               5,     65, second_thread_pool,        false, false, true  }, 
    { MINUTE_SCRIPT_DIR,                   60,     60, minute_thread_pool,        false, false, true  },
    { FIVE_MINUTES_SCRIPT_DIR,            300,    300, five_minute_thread_pool,   false, false, true  },
    { HOURLY_SCRIPT_DIR,                 3600,    600, hourly_thread_pool,        false, false, true  },
    { DAILY_SCRIPT_DIR,                 86400,   3600, daily_thread_pool,         true,  false, true  },

    /* TODO: remove these two periodic scripts */
    { HOUSEKEEPING_SCRIPT_PATH,             3,     65, housekeeping_pool,         false, false, false }, 
    { NULL,                                 0,      0, NULL,                      false, false, false }
  };

  activity_descr *d = ad;
  
  while(d->path) {
    std::vector<char*> iface_scripts_list, system_scripts_list;
    u_int8_t num_threads = ntop->get_num_interfaces() + 1; /* System interface */
    
    if(num_threads > MAX_THREAD_POOL_SIZE)
      num_threads = MAX_THREAD_POOL_SIZE;

    if(num_threads) {
      d->pool = new (std::nothrow) ThreadPool(false, num_threads);

      ntop->getTrace()->traceEvent(TRACE_NORMAL, "Periodic %s scripts will use %u threads", d->path, num_threads);
  
      ThreadedActivity *ta = new (std::nothrow) ThreadedActivity(d->path,
						d->periodicity,
						d->max_duration_secs,
						d->align_to_localtime,
						d->exclude_viewed_interfaces,
						d->exclude_pcap_dump_interfaces,
						d->pool);
      if(ta) {
        activities[num_activities++] = ta;
        ta->run();
      }
    }

    d++;
  }
}

/* ******************************************* */
