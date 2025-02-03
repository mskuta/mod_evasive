/*
mod_evasive for Apache 2
Copyright (c) by Jonathan A. Zdziarski

LICENSE

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/

#include <stdbool.h>

// clang-format off
#include "ap_socache.h"
#include "apr_cstr.h"
#include "apr_strings.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"
#include "util_mutex.h"
// clang-format on

#define MUTEXTYPE_BLOCK   "evasive20-block"
#define MUTEXTYPE_PAGE    "evasive20-page"
#define MUTEXTYPE_SITE    "evasive20-site"

#define WHITELIST_NUM_MAX 10
#define WHITELIST_IP_SIZE 40

module AP_MODULE_DECLARE_DATA evasive20_module;
static char errorstr[MAX_STRING_LEN];
typedef struct {
	int on;
	unsigned int page_count;
	unsigned int site_count;
	apr_interval_time_t blocking_period;
	apr_interval_time_t page_interval;
	apr_interval_time_t site_interval;
	apr_global_mutex_t* cache_mutex_block;
	apr_global_mutex_t* cache_mutex_page;
	apr_global_mutex_t* cache_mutex_site;
	ap_socache_instance_t* cache_instance_block;
	ap_socache_instance_t* cache_instance_page;
	ap_socache_instance_t* cache_instance_site;
	ap_socache_provider_t* cache_provider;
	unsigned whitelist_num;
	char whitelist_ip[WHITELIST_NUM_MAX][WHITELIST_IP_SIZE];
} evasive20_config;

static void unlock_mutex(apr_global_mutex_t* mutex, request_rec* r) {
	const apr_status_t status = apr_global_mutex_unlock(mutex);
	if (status != APR_SUCCESS)
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r, "failed to release lock on mutex: %s", apr_strerror(status, errorstr, sizeof errorstr));
}

static bool is_mutex_locked(apr_global_mutex_t* mutex, request_rec* r) {
	const apr_status_t status = apr_global_mutex_trylock(mutex);
	if (status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, status == APR_EBUSY ? APLOG_NOTICE : APLOG_WARNING, status, r, "failed to acquire lock on mutex: %s", apr_strerror(status, errorstr, sizeof errorstr));
		return false;
	}
	return true;
}

static int evasive20_access_checker(request_rec* r) {
	// ignore sub-requests
	if (r->main)
		return DECLINED;

	const evasive20_config* const config = (evasive20_config*)ap_get_module_config(r->server->module_config, &evasive20_module);
	if (!config->on)
		return DECLINED;

	// cancel here if this IP is to be ignored
	for (unsigned i = 0; i < config->whitelist_num; i++)
		if (ap_strcmp_match(r->useragent_ip, config->whitelist_ip[i]) == 0) {
			ap_log_rerror(APLOG_MARK, APLOG_INFO, APR_SUCCESS, r, "IP is whitelisted: %s", r->useragent_ip);
			return DECLINED;
		}

	// IPs cannot be tracked without caches
	if (!(config->cache_instance_block && config->cache_instance_page && config->cache_instance_site)) {
		ap_log_rerror(APLOG_MARK, APLOG_NOTICE, APR_SUCCESS, r, "some cache was not instantiated");
		return DECLINED;
	}

	const apr_time_t blocking_time = r->request_time + config->blocking_period;
	bool is_blocked = false;
	struct {
		unsigned int count;
	} data;
	unsigned int datalen;
	apr_status_t status;
	datalen = sizeof data;
	status = config->cache_provider->retrieve(config->cache_instance_block, r->server, r->useragent_ip, strlen(r->useragent_ip), (unsigned char*)&data, &datalen, r->pool);
	if (status == APR_SUCCESS) {
		is_blocked = true;

		// continue to block IP
		if (is_mutex_locked(config->cache_mutex_block, r)) {
			datalen = sizeof data;
			status = config->cache_provider->store(config->cache_instance_block, r->server, r->useragent_ip, strlen(r->useragent_ip), blocking_time, (unsigned char*)&data, datalen, r->pool);
			if (status == APR_SUCCESS)
				ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r, "blocking period extended for IP: %s", r->useragent_ip);
			else
				ap_log_rerror(APLOG_MARK, APLOG_WARNING, status, r, "failed to extend blocking period for IP: %s", r->useragent_ip);
			unlock_mutex(config->cache_mutex_block, r);
		}
	}
	else if (status == APR_NOTFOUND) {
		unsigned char id[2048];

		// check whether the page has been hit too often
		snprintf(id, sizeof id, "%s_%s_%s", r->useragent_ip, r->server->server_hostname, r->parsed_uri.path ? r->parsed_uri.path : "/");
		datalen = sizeof data;
		status = config->cache_provider->retrieve(config->cache_instance_page, r->server, id, strlen(id), (unsigned char*)&data, &datalen, r->pool);
		if (status == APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "page entry found for id: %s (count: %d)", id, data.count);
			data.count++;
			if (data.count > config->page_count) {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "page limit exceeded for id: %s", id);

				// begin to block IP
				if (is_mutex_locked(config->cache_mutex_block, r)) {
					datalen = sizeof data;
					status = config->cache_provider->store(config->cache_instance_block, r->server, r->useragent_ip, strlen(r->useragent_ip), blocking_time, (unsigned char*)&data, datalen, r->pool);
					if (status == APR_SUCCESS) {
						ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r, "blocking period started for IP: %s", r->useragent_ip);
						is_blocked = true;
					}
					else
						ap_log_rerror(APLOG_MARK, APLOG_WARNING, status, r, "failed to start blocking period for IP: %s", r->useragent_ip);
					unlock_mutex(config->cache_mutex_block, r);
				}
			}
			else {
				if (is_mutex_locked(config->cache_mutex_page, r)) {
					datalen = sizeof data;
					status = config->cache_provider->store(config->cache_instance_page, r->server, id, strlen(id), r->request_time + config->page_interval, (unsigned char*)&data, datalen, r->pool);
					if (status == APR_SUCCESS)
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "page entry updated for id: %s", id);
					else
						ap_log_rerror(APLOG_MARK, APLOG_WARNING, status, r, "failed to update page entry for id: %s", id);
					unlock_mutex(config->cache_mutex_page, r);
				}
			}
		}
		else if (status == APR_NOTFOUND) {
			data.count = 1;
			if (is_mutex_locked(config->cache_mutex_page, r)) {
				datalen = sizeof data;
				status = config->cache_provider->store(config->cache_instance_page, r->server, id, strlen(id), r->request_time + config->page_interval, (unsigned char*)&data, datalen, r->pool);
				if (status == APR_SUCCESS)
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "page entry inserted for id: %s", id);
				else
					ap_log_rerror(APLOG_MARK, APLOG_WARNING, status, r, "failed to insert page entry for id: %s", id);
				unlock_mutex(config->cache_mutex_page, r);
			}
		}
		else
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, status, r, "failed to retrieve page entry for id: %s", id);

		// check whether the site has been hit too often
		snprintf(id, sizeof id, "%s_%s", r->useragent_ip, r->server->server_hostname);
		datalen = sizeof data;
		status = config->cache_provider->retrieve(config->cache_instance_site, r->server, id, strlen(id), (unsigned char*)&data, &datalen, r->pool);
		if (status == APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "site entry found for id: %s (count: %d)", id, data.count);
			data.count++;
			if (data.count > config->site_count) {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "site limit exceeded for id: %s", id);

				// begin to block IP
				if (is_mutex_locked(config->cache_mutex_block, r)) {
					datalen = sizeof data;
					status = config->cache_provider->store(config->cache_instance_block, r->server, r->useragent_ip, strlen(r->useragent_ip), blocking_time, (unsigned char*)&data, datalen, r->pool);
					if (status == APR_SUCCESS) {
						ap_log_rerror(APLOG_MARK, APLOG_INFO, status, r, "blocking period started for IP: %s", r->useragent_ip);
						is_blocked = true;
					}
					else
						ap_log_rerror(APLOG_MARK, APLOG_WARNING, status, r, "failed to start blocking period for IP: %s", r->useragent_ip);
					unlock_mutex(config->cache_mutex_block, r);
				}
			}
			else {
				if (is_mutex_locked(config->cache_mutex_site, r)) {
					datalen = sizeof data;
					status = config->cache_provider->store(config->cache_instance_site, r->server, id, strlen(id), r->request_time + config->site_interval, (unsigned char*)&data, datalen, r->pool);
					if (status == APR_SUCCESS)
						ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "site entry updated for id: %s", id);
					else
						ap_log_rerror(APLOG_MARK, APLOG_WARNING, status, r, "failed to update site entry for id: %s", id);
					unlock_mutex(config->cache_mutex_site, r);
				}
			}
		}
		else if (status == APR_NOTFOUND) {
			data.count = 1;
			datalen = sizeof data;
			if (is_mutex_locked(config->cache_mutex_site, r)) {
				status = config->cache_provider->store(config->cache_instance_site, r->server, id, strlen(id), r->request_time + config->site_interval, (unsigned char*)&data, datalen, r->pool);
				if (status == APR_SUCCESS)
					ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "site entry inserted for id: %s", id);
				else
					ap_log_rerror(APLOG_MARK, APLOG_WARNING, status, r, "failed to insert site entry for id: %s", id);
				unlock_mutex(config->cache_mutex_site, r);
			}
		}
		else
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, status, r, "failed to retrieve site entry for id: %s", id);
	}
	else
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, status, r, "failed to retrieve entry fo IP: %s", r->useragent_ip);

	return is_blocked ? HTTP_TOO_MANY_REQUESTS : DECLINED;
}

static apr_status_t cleanup_mutex_block(void* data) {
	server_rec* s = data;
	evasive20_config* const config = (evasive20_config*)ap_get_module_config(s->module_config, &evasive20_module);
	apr_global_mutex_destroy(config->cache_mutex_block);
	config->cache_mutex_block = NULL;
	return APR_SUCCESS;
}

static apr_status_t cleanup_mutex_page(void* data) {
	server_rec* s = data;
	evasive20_config* const config = (evasive20_config*)ap_get_module_config(s->module_config, &evasive20_module);
	apr_global_mutex_destroy(config->cache_mutex_page);
	config->cache_mutex_page = NULL;
	return APR_SUCCESS;
}

static apr_status_t cleanup_mutex_site(void* data) {
	server_rec* s = data;
	evasive20_config* const config = (evasive20_config*)ap_get_module_config(s->module_config, &evasive20_module);
	apr_global_mutex_destroy(config->cache_mutex_site);
	config->cache_mutex_site = NULL;
	return APR_SUCCESS;
}

static apr_status_t cleanup_cache_block(void* data) {
	server_rec* s = data;
	evasive20_config* const config = (evasive20_config*)ap_get_module_config(s->module_config, &evasive20_module);
	config->cache_provider->destroy(config->cache_instance_block, s);
	config->cache_instance_block = NULL;
	return APR_SUCCESS;
}

static apr_status_t cleanup_cache_page(void* data) {
	server_rec* s = data;
	evasive20_config* const config = (evasive20_config*)ap_get_module_config(s->module_config, &evasive20_module);
	config->cache_provider->destroy(config->cache_instance_page, s);
	config->cache_instance_page = NULL;
	return APR_SUCCESS;
}

static apr_status_t cleanup_cache_site(void* data) {
	server_rec* s = data;
	evasive20_config* const config = (evasive20_config*)ap_get_module_config(s->module_config, &evasive20_module);
	config->cache_provider->destroy(config->cache_instance_site, s);
	config->cache_instance_site = NULL;
	return APR_SUCCESS;
}

static int evasive20_pre_config(apr_pool_t* pcfg, apr_pool_t* plog, apr_pool_t* ptmp) {
	apr_status_t status;

	// register block mutex
	status = ap_mutex_register(pcfg, MUTEXTYPE_BLOCK, NULL, APR_LOCK_DEFAULT, 0);
	if (status != APR_SUCCESS) {
		ap_log_perror(APLOG_MARK, APLOG_CRIT, status, plog, "failed to register mutex (block): %s", apr_strerror(status, errorstr, sizeof errorstr));
		return !OK;
	}

	// register page mutex
	status = ap_mutex_register(pcfg, MUTEXTYPE_PAGE, NULL, APR_LOCK_DEFAULT, 0);
	if (status != APR_SUCCESS) {
		ap_log_perror(APLOG_MARK, APLOG_CRIT, status, plog, "failed to register mutex (page): %s", apr_strerror(status, errorstr, sizeof errorstr));
		return !OK;
	}

	// register site mutex
	status = ap_mutex_register(pcfg, MUTEXTYPE_SITE, NULL, APR_LOCK_DEFAULT, 0);
	if (status != APR_SUCCESS) {
		ap_log_perror(APLOG_MARK, APLOG_CRIT, status, plog, "failed to register mutex (site): %s", apr_strerror(status, errorstr, sizeof errorstr));
		return !OK;
	}

	return OK;
}

static int evasive20_post_config(apr_pool_t* pcfg, apr_pool_t* plog, apr_pool_t* ptmp, server_rec* s) {
	for (server_rec* vhost = s; vhost; vhost = vhost->next) {
		evasive20_config* const config = (evasive20_config*)ap_get_module_config(vhost->module_config, &evasive20_module);
		if (!config->on)
			continue;

		// check config
		if (config->blocking_period < config->page_interval)
			ap_log_perror(APLOG_MARK, APLOG_NOTICE, APR_SUCCESS, plog, "configured blocking period shall be longer than page interval");
		if (config->blocking_period < config->site_interval)
			ap_log_perror(APLOG_MARK, APLOG_NOTICE, APR_SUCCESS, plog, "configured blocking period shall be longer than site interval");
		if (!config->cache_provider)
			ap_log_perror(APLOG_MARK, APLOG_NOTICE, APR_SUCCESS, plog, "configured cache provider not found");
		else {
			apr_status_t status;

			// instantiate block cache
			status = ap_global_mutex_create(&config->cache_mutex_block, NULL, MUTEXTYPE_BLOCK, NULL, vhost, pcfg, 0);
			if (status != APR_SUCCESS) {
				ap_log_perror(APLOG_MARK, APLOG_CRIT, status, plog, "failed to create mutex (block): %s", apr_strerror(status, errorstr, sizeof errorstr));
				return !OK;
			}
			apr_pool_cleanup_register(pcfg, (void*)vhost, cleanup_mutex_block, apr_pool_cleanup_null);
			status = config->cache_provider->init(config->cache_instance_block, MUTEXTYPE_BLOCK, NULL, vhost, pcfg);
			if (status != APR_SUCCESS) {
				ap_log_perror(APLOG_MARK, APLOG_CRIT, status, plog, "failed to initialize cache (block): %s", apr_strerror(status, errorstr, sizeof errorstr));
				return !OK;
			}
			apr_pool_cleanup_register(pcfg, (void*)vhost, cleanup_cache_block, apr_pool_cleanup_null);

			// instantiate page cache
			status = ap_global_mutex_create(&config->cache_mutex_page, NULL, MUTEXTYPE_PAGE, NULL, vhost, pcfg, 0);
			if (status != APR_SUCCESS) {
				ap_log_perror(APLOG_MARK, APLOG_CRIT, status, plog, "failed to create mutex (page): %s", apr_strerror(status, errorstr, sizeof errorstr));
				return !OK;
			}
			apr_pool_cleanup_register(pcfg, (void*)vhost, cleanup_mutex_page, apr_pool_cleanup_null);
			status = config->cache_provider->init(config->cache_instance_page, MUTEXTYPE_PAGE, NULL, vhost, pcfg);
			if (status != APR_SUCCESS) {
				ap_log_perror(APLOG_MARK, APLOG_CRIT, status, plog, "failed to initialize cache (page): %s", apr_strerror(status, errorstr, sizeof errorstr));
				return !OK;
			}
			apr_pool_cleanup_register(pcfg, (void*)vhost, cleanup_cache_page, apr_pool_cleanup_null);

			// instantiate site cache
			status = ap_global_mutex_create(&config->cache_mutex_site, NULL, MUTEXTYPE_SITE, NULL, vhost, pcfg, 0);
			if (status != APR_SUCCESS) {
				ap_log_perror(APLOG_MARK, APLOG_CRIT, status, plog, "failed to create mutex (site): %s", apr_strerror(status, errorstr, sizeof errorstr));
				return !OK;
			}
			apr_pool_cleanup_register(pcfg, (void*)vhost, cleanup_mutex_site, apr_pool_cleanup_null);
			status = config->cache_provider->init(config->cache_instance_site, MUTEXTYPE_SITE, NULL, vhost, pcfg);
			if (status != APR_SUCCESS) {
				ap_log_perror(APLOG_MARK, APLOG_CRIT, status, plog, "failed to initialize cache (site): %s", apr_strerror(status, errorstr, sizeof errorstr));
				return !OK;
			}
			apr_pool_cleanup_register(pcfg, (void*)vhost, cleanup_cache_site, apr_pool_cleanup_null);
		}
	}
	return OK;
}

static void* create_server_config(apr_pool_t* p, server_rec* s) {
	evasive20_config* const config = apr_pcalloc(p, sizeof(evasive20_config));
	if (config) {
		// set default values
		config->on = 0;  // false
		config->page_count = 2;
		config->site_count = 50;
		config->page_interval = apr_time_from_sec(1);
		config->site_interval = apr_time_from_sec(1);
		config->blocking_period = apr_time_from_sec(10);
		config->whitelist_num = 0;

		// set these after the entire configuration has been read
		config->cache_mutex_block = config->cache_mutex_page = config->cache_mutex_site = NULL;
		config->cache_instance_block = config->cache_instance_page = config->cache_instance_site = NULL;
		config->cache_provider = NULL;
	}
	else
		ap_log_error(APLOG_MARK, APLOG_CRIT, apr_get_os_error(), s, "failed to allocate memory for configuration");
	return config;
}

static const char* set_page_count(cmd_parms* cmd, void* dconfig, const char* value) {
	unsigned int n;
	const apr_status_t status = apr_cstr_atoui(&n, value);
	if (status == APR_SUCCESS) {
		evasive20_config* const mconfig = (evasive20_config*)ap_get_module_config(cmd->server->module_config, &evasive20_module);
		mconfig->page_count = n;
		return NULL;
	}
	return apr_strerror(status, errorstr, sizeof errorstr);
}

static const char* set_site_count(cmd_parms* cmd, void* dconfig, const char* value) {
	unsigned int n;
	const apr_status_t status = apr_cstr_atoui(&n, value);
	if (status == APR_SUCCESS) {
		evasive20_config* const mconfig = (evasive20_config*)ap_get_module_config(cmd->server->module_config, &evasive20_module);
		mconfig->site_count = n;
		return NULL;
	}
	return apr_strerror(status, errorstr, sizeof errorstr);
}

static const char* set_page_interval(cmd_parms* cmd, void* dconfig, const char* value) {
	unsigned int n;
	const apr_status_t status = apr_cstr_atoui(&n, value);
	if (status == APR_SUCCESS) {
		evasive20_config* const mconfig = (evasive20_config*)ap_get_module_config(cmd->server->module_config, &evasive20_module);
		mconfig->page_interval = apr_time_from_sec(n);
		return NULL;
	}
	return apr_strerror(status, errorstr, sizeof errorstr);
}

static const char* set_site_interval(cmd_parms* cmd, void* dconfig, const char* value) {
	unsigned int n;
	const apr_status_t status = apr_cstr_atoui(&n, value);
	if (status == APR_SUCCESS) {
		evasive20_config* const mconfig = (evasive20_config*)ap_get_module_config(cmd->server->module_config, &evasive20_module);
		mconfig->site_interval = apr_time_from_sec(n);
		return NULL;
	}
	return apr_strerror(status, errorstr, sizeof errorstr);
}

static const char* set_blocking_period(cmd_parms* cmd, void* dconfig, const char* value) {
	unsigned int n;
	const apr_status_t status = apr_cstr_atoui(&n, value);
	if (status == APR_SUCCESS) {
		evasive20_config* const mconfig = (evasive20_config*)ap_get_module_config(cmd->server->module_config, &evasive20_module);
		mconfig->blocking_period = apr_time_from_sec(n);
		return NULL;
	}
	return apr_strerror(status, errorstr, sizeof errorstr);
}

static const char* set_whitelist(cmd_parms* cmd, void* dconfig, const char* value) {
	evasive20_config* const mconfig = (evasive20_config*)ap_get_module_config(cmd->server->module_config, &evasive20_module);
	if (mconfig->whitelist_num < WHITELIST_NUM_MAX)
		snprintf(mconfig->whitelist_ip[mconfig->whitelist_num++], WHITELIST_IP_SIZE, "%s", value);
	return NULL;
}

static const char* set_cache(cmd_parms* cmd, void* dconfig, const char* value) {
	// value has the form provider-name[:provider-args]
	const char* name;
	const char* args = ap_strchr_c(value, ':');
	if (args) {
		name = apr_pstrmemdup(cmd->pool, value, args - value);
		args++;
	}
	else
		name = value;

	evasive20_config* const mconfig = (evasive20_config*)ap_get_module_config(cmd->server->module_config, &evasive20_module);
	mconfig->cache_provider = ap_lookup_provider(AP_SOCACHE_PROVIDER_GROUP, name, AP_SOCACHE_PROVIDER_VERSION);
	if (mconfig->cache_provider) {
		const char* err;

		// create block cache
		if ((err = mconfig->cache_provider->create(&mconfig->cache_instance_block, args, cmd->temp_pool, cmd->pool)))
			return apr_psprintf(cmd->pool, "failed to create cache (block): %s", err);

		// create page cache
		if ((err = mconfig->cache_provider->create(&mconfig->cache_instance_page, args, cmd->temp_pool, cmd->pool)))
			return apr_psprintf(cmd->pool, "failed to create cache (page): %s", err);

		// create site cache
		if ((err = mconfig->cache_provider->create(&mconfig->cache_instance_site, args, cmd->temp_pool, cmd->pool)))
			return apr_psprintf(cmd->pool, "failed to create cache (site): %s", err);
	}
	else
		return apr_psprintf(cmd->pool, "failed to lookup cache provider: %s", name);
	return NULL;
}

static const char* set_engine(cmd_parms* cmd, void* dconfig, int value) {
	evasive20_config* const mconfig = (evasive20_config*)ap_get_module_config(cmd->server->module_config, &evasive20_module);
	mconfig->on = value;
	return NULL;
}

// clang-format off
static const command_rec evasive20_cmds[] = {
	AP_INIT_FLAG("DOSEngine", set_engine, NULL, RSRC_CONF, "Switch on the functionality within the given context"),
	AP_INIT_TAKE1("DOSPageCount", set_page_count, NULL, RSRC_CONF, "Set maximum page hit count per interval"),
	AP_INIT_TAKE1("DOSSiteCount", set_site_count, NULL, RSRC_CONF, "Set maximum site hit count per interval"),
	AP_INIT_TAKE1("DOSPageInterval", set_page_interval, NULL, RSRC_CONF, "Set page interval in seconds"),
	AP_INIT_TAKE1("DOSSiteInterval", set_site_interval, NULL, RSRC_CONF, "Set site interval in seconds"),
	AP_INIT_TAKE1("DOSBlockingPeriod", set_blocking_period, NULL, RSRC_CONF, "Set blocking period in seconds for detected IPs"),
	AP_INIT_ITERATE("DOSWhitelist", set_whitelist, NULL, RSRC_CONF, "Set IPs to be ignored, also as wildcards"),
	AP_INIT_TAKE1("DOSCache", set_cache, NULL, RSRC_CONF, "Set cache provider"),
	{ NULL }
};
// clang-format on

static void register_hooks(apr_pool_t* p) {
	ap_hook_pre_config(evasive20_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_post_config(evasive20_post_config, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_access_checker(evasive20_access_checker, NULL, NULL, APR_HOOK_FIRST);
};

// clang-format off
AP_DECLARE_MODULE(evasive20) = {
	STANDARD20_MODULE_STUFF,
	NULL,
	NULL,
	create_server_config,
	NULL,
	evasive20_cmds,
	register_hooks
};
// clang-format on
