# https://gist.github.com/peterjaap/7f7bf11aa7d089792e8fcc2fb34760fa 

import cookie;
import xkey;

# Add hostnames, IP addresses and subnets that are allowed to purge content
#https://docs.platform.sh/development/regions.html#:~:text=52.208.123.9,52.30.200.164
acl purge {
    "localhost";
    "127.0.0.1";
    "52.214.63.84";
    "52.208.123.9";
    "52.30.200.164";
}

sub vcl_recv {

    #https://docs.upsun.com/add-services/varnish.html#2-create-a-vcl-template:~:text=sub%20vcl_recv%20%7B-,set%20req.backend_hint%20%3D%20application.backend()%3B,-%7D 
    set req.backend_hint = application.backend();

    # Remove empty query string parameters
    # e.g.: www.example.com/index.html?    
    if (req.url ~ "\?$") {
        set req.url = regsub(req.url, "\?$", "");
    }

    # Remove port number from host header if set
    if (req.http.Host ~ ":[0-9]+$") {
        set req.http.Host = regsub(req.http.Host, ":[0-9]+$", "");
    }

    # Sorts query string parameters alphabetically for cache normalization purposes, only when there are multiple parameters
    if (req.url ~ "\?.+&.+") {
        set req.url = std.querysort(req.url);
    }

    # Reduce grace to the configured setting if the backend is healthy
    # In case of an unhealthy backend, the original grace is used
    if (std.healthy(req.backend_hint)) {
        set req.grace = 5s;
    }
    
    # Purge logic to remove objects from the cache
    # Tailored to Magento's cache invalidation mechanism and Platform.SH X-Client-IP
    # The X-Magento-Tags-Pattern value is matched to the tags in the X-Magento-Tags header
    # If X-Magento-Tags-Pattern is not set, a URL-based purge is executed
    if (req.method == "PURGE") {
        if (!std.ip(req.http.X-Client-IP, "0.0.0.0") ~ purge) {
            return (synth(405));
        }

        # If the X-Magento-Tags-Pattern header is not set, just use regular URL-based purge
        if (!req.http.X-Magento-Tags-Pattern) {
            return (purge);
        }

        # Full Page Cache flush
        if (req.http.X-Magento-Tags-Pattern == ".*") {
            if (0) { # CONFIGURABLE: soft purge
                set req.http.n-gone = xkey.softpurge("all");
            } else {
                set req.http.n-gone = xkey.purge("all");
            }
            return (synth(200, "Invalidated " + req.http.n-gone + " objects full flush"));
        } else if (req.http.X-Magento-Tags-Pattern) {
            # replace "((^|,)cat_c(,|$))|((^|,)cat_p(,|$))" to be "cat_c,cat_p"
            set req.http.X-Magento-Tags-Pattern = regsuball(req.http.X-Magento-Tags-Pattern, "[^a-zA-Z0-9_-]+" ,",");
            set req.http.X-Magento-Tags-Pattern = regsuball(req.http.X-Magento-Tags-Pattern, "(^,*)|(,*$)" ,"");
            if ( 1 ) { # CONFIGURABLE: Use softpurge
                set req.http.n-gone = xkey.softpurge(req.http.X-Magento-Tags-Pattern);
            } else {
                set req.http.n-gone = xkey.purge(req.http.X-Magento-Tags-Pattern);
            }
            return (synth(200, "Invalidated " + req.http.n-gone + " objects"));
        }

        return (synth(200, "Purged"));
    }

    if (req.method != "GET" &&
        req.method != "HEAD" &&
        req.method != "PUT" &&
        req.method != "POST" &&
        req.method != "PATCH" &&
        req.method != "TRACE" &&
        req.method != "OPTIONS" &&
        req.method != "DELETE") {
          return (pipe);
    }

    # We only deal with GET and HEAD by default
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    # Collapse multiple cookie headers into one
    std.collect(req.http.Cookie, ";");

    # Parse the cookie header
    cookie.parse(req.http.cookie);

    # Add support for Prismic preview functionality
    # TODO MAKE CONFIGURABLE, DO NOT HARD-CODE PRISMIC HOST
    if (cookie.isset("io.prismic.preview")) {
        return (pass);
    }

    # Remove all marketing get parameters to minimize the cache objects
    # TODO MAKE CONFIGURABLE
    if (req.url ~ "(\?|&)(_branch_match_id|srsltid|_bta_c|_bta_tid|_ga|_gl|_ke|_kx|campid|cof|customid|cx|dclid|dm_i|ef_id|epik|fbclid|gad_source|gbraid|gclid|gclsrc|gdffi|gdfms|gdftrk|hsa_acc|hsa_ad|hsa_cam|hsa_grp|hsa_kw|hsa_mt|hsa_net|hsa_src|hsa_tgt|hsa_ver|ie|igshid|irclickid|matomo_campaign|matomo_cid|matomo_content|matomo_group|matomo_keyword|matomo_medium|matomo_placement|matomo_source|mc_cid|mc_eid|mkcid|mkevt|mkrid|mkwid|msclkid|mtm_campaign|mtm_cid|mtm_content|mtm_group|mtm_keyword|mtm_medium|mtm_placement|mtm_source|nb_klid|ndclid|origin|pcrid|piwik_campaign|piwik_keyword|piwik_kwd|pk_campaign|pk_keyword|pk_kwd|redirect_log_mongo_id|redirect_mongo_id|rtid|sb_referer_host|ScCid|si|siteurl|s_kwcid|sms_click|sms_source|sms_uph|toolid|trk_contact|trk_module|trk_msg|trk_sid|ttclid|twclid|utm_campaign|utm_content|utm_creative_format|utm_id|utm_marketing_tactic|utm_medium|utm_source|utm_source_platform|utm_term|wbraid|yclid|zanpid|mc_[a-z]+|utm_[a-z]+|_bta_[a-z]+)=") {
        set req.url = regsuball(req.url, "(_branch_match_id|srsltid|_bta_c|_bta_tid|_ga|_gl|_ke|_kx|campid|cof|customid|cx|dclid|dm_i|ef_id|epik|fbclid|gad_source|gbraid|gclid|gclsrc|gdffi|gdfms|gdftrk|hsa_acc|hsa_ad|hsa_cam|hsa_grp|hsa_kw|hsa_mt|hsa_net|hsa_src|hsa_tgt|hsa_ver|ie|igshid|irclickid|matomo_campaign|matomo_cid|matomo_content|matomo_group|matomo_keyword|matomo_medium|matomo_placement|matomo_source|mc_cid|mc_eid|mkcid|mkevt|mkrid|mkwid|msclkid|mtm_campaign|mtm_cid|mtm_content|mtm_group|mtm_keyword|mtm_medium|mtm_placement|mtm_source|nb_klid|ndclid|origin|pcrid|piwik_campaign|piwik_keyword|piwik_kwd|pk_campaign|pk_keyword|pk_kwd|redirect_log_mongo_id|redirect_mongo_id|rtid|sb_referer_host|ScCid|si|siteurl|s_kwcid|sms_click|sms_source|sms_uph|toolid|trk_contact|trk_module|trk_msg|trk_sid|ttclid|twclid|utm_campaign|utm_content|utm_creative_format|utm_id|utm_marketing_tactic|utm_medium|utm_source|utm_source_platform|utm_term|wbraid|yclid|zanpid|mc_[a-z]+|utm_[a-z]+|_bta_[a-z]+)=[-_A-z0-9+(){}%.]+&?", "");
        set req.url = regsub(req.url, "[?|&]+$", "");
    }

    # Media files caching
    if (req.url ~ "^/(pub/)?media/") {
        if ( 1 ) { # TODO MAKE CONFIGURABLE: Cache media files
            unset req.http.Https;
            unset req.http.X-Forwarded-Proto;
            unset req.http.Cookie;
        } else {
            return (pass);
        }
    }

    # Static files caching
    if (req.url ~ "^/(pub/)?static/") {
        if ( 1 ) { # TODO MAKE CONFIGURABLE: Cache static files
            unset req.http.Https;
            unset req.http.X-Forwarded-Proto;
            unset req.http.Cookie;
        } else {
            return (pass);
        }
    }

    # Don't cache the authenticated GraphQL requests
    if (req.url ~ "/graphql" && req.http.Authorization ~ "^Bearer") {
        return (pass);
    }

    return (hash);
}

sub vcl_hash {
    if (req.url !~ "/graphql" && cookie.isset("X-Magento-Vary=")) {
        hash_data(cookie.get("X-Magento-Vary"));
    }

    # To make sure http users don't see ssl warning
    hash_data(req.http.X-Forwarded-Proto);
    
    /* {{ design_exceptions_code }} */

    if (req.url ~ "/graphql") {
        call process_graphql_headers;
    }
}

sub process_graphql_headers {
    if (req.http.X-Magento-Cache-Id) {
        hash_data(req.http.X-Magento-Cache-Id);

        # When the frontend stops sending the auth token, make sure users stop getting results cached for logged-in users
        if (req.http.Authorization ~ "^Bearer") {
            hash_data("Authorized");
        }
    }

    if (req.http.Store) {
        hash_data(req.http.Store);
    }

    if (req.http.Content-Currency) {
        hash_data(req.http.Content-Currency);
    }
}

sub vcl_backend_response {
    # Serve stale content for one days after object expiration
    # Perform asynchronous revalidation while stale content is served
    set beresp.grace = 1d;

    if (beresp.http.X-Magento-Tags) {
        # set comma separated xkey with "all" tag
        set beresp.http.XKey = beresp.http.X-Magento-Tags + ",all";
        unset beresp.http.X-Magento-Tags;
    }

    # All text-based content can be parsed as ESI
    if (beresp.http.content-type ~ "text") {
        set beresp.do_esi = true;
    }

    # Cache HTTP 200 responses
    # TODO MAKE CONFIGURABLE whether or not 404's should be cached
    if (beresp.status != 200 && beresp.status != 404) {
    #if (beresp.status != 200) {
        set beresp.ttl = 120s;
        set beresp.uncacheable = true;
        return (deliver);
    }
    
    # Don't cache if the request cache ID doesn't match the response cache ID for graphql requests
    if (bereq.url ~ "/graphql" && bereq.http.X-Magento-Cache-Id && bereq.http.X-Magento-Cache-Id != beresp.http.X-Magento-Cache-Id) {
       set beresp.ttl = 120s;
       set beresp.uncacheable = true;
       return (deliver);
    }

    # Remove the Set-Cookie header for cacheable content
    # Only for HTTP GET & HTTP HEAD requests
    if (beresp.ttl > 0s && (bereq.method == "GET" || bereq.method == "HEAD")) {
        unset beresp.http.Set-Cookie;
    }
}

sub vcl_deliver {
    if (obj.uncacheable) {
        set resp.http.X-Magento-Cache-Debug = "UNCACHEABLE";
    } else if (obj.hits) {
        set resp.http.X-Magento-Cache-Debug = "HIT";
        set resp.http.Grace = req.http.grace;
    } else {
        set resp.http.X-Magento-Cache-Debug = "MISS";
    }

    # Let browser and Cloudflare cache non-static content that are cacheable for short period of time
    if (resp.http.Cache-Control !~ "private" && req.url !~ "^/(media|static)/" && obj.ttl > 0s) {
        set resp.http.Cache-Control = "must-revalidate, max-age=120";
        if ( 0 ) { # TODO MAKE CONFIGURABLE: Enable/disable backward-forward cache (default enabled)
            set resp.http.Cache-Control = resp.http.Cache-Control + ", no-store";
        }
    }

    unset resp.http.XKey;
    unset resp.http.Expires;
    unset resp.http.Pragma;
    unset resp.http.X-Magento-Debug;
    unset resp.http.X-Magento-Tags;
    unset resp.http.X-Powered-By;
    unset resp.http.Server;
    unset resp.http.X-Varnish;
    unset resp.http.Via;
    unset resp.http.Link;
}
