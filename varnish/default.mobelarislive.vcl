vcl 4.0;

import std;
# The minimal Varnish version is 4.0
# For SSL offloading, pass the following header in your proxy server or load balancer: 'X-Forwarded-Proto: https'

backend default {
    .host = "127.0.0.1";
    .port = "8080";
    .first_byte_timeout = 300s;
}
acl purge {
    "35.214.6.51";
}

sub vcl_recv {
    if (req.http.host ~ "varnish\.mobelaris\.com") {
        if (client.ip !~ purge) {
            return (synth(405, "Method not allowed"));
        }
        if (!req.http.X-Magento-Tags-Pattern) {
            return (synth(400, "X-Magento-Tags-Pattern header required"));
        }
        ban("obj.http.X-Magento-Tags ~ " + req.http.X-Magento-Tags-Pattern);
        return (synth(200, "Purged"));
    }

    if (req.url ~ "/hieuflushvarnish") {
        if (client.ip !~ purge) {
            return (synth(405, "Method not allowed"));
        }
        ban("req.http.host ~ .*");
        return (synth(200, "Purged"));
    }

    if (req.url ~ "/hieuflushvarnishpage") {
        if (client.ip !~ purge) {
            return (synth(405, "Method not allowed"));
        }
        ban("obj.http.X-Magento-Tags ~ " + req.http.X-Magento-Tags-Pattern);
        return (synth(200, "Purged"));
    }

#    if (req.http.CF-IPCountry) {
#        set req.http.X-Country = req.http.CF-IPCountry;
#    }

#    if (req.url ~ "/en/" && (req.http.X-Country == "DK" || req.http.X-Country == "IT" || req.http.X-Country == "DE")) {
#        return (pass);
#    }

    if (req.method != "GET" &&
        req.method != "HEAD" &&
        req.method != "PUT" &&
        req.method != "POST" &&
        req.method != "TRACE" &&
        req.method != "OPTIONS" &&
        req.method != "DELETE") {
          /* Non-RFC2616 or CONNECT which is weird. */
          return (pipe);
    }

    # We only deal with GET and HEAD by default
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }

    # pass the cache for updown
   # if (req.http.User-Agent ~ "updown.io daemon 2.4") {
    #    return (pass);
   # }
#	if (req.http.User-Agent ~ "bot" || req.http.User-Agent ~ "google") {
#		return (pass);
#	}
    # Bypass shopping cart, checkout and search requests
    if (req.url ~ "/checkout" || req.url ~ "/catalogsearch" || req.url ~ "/admin" || req.url ~ "/wpde-blog") {
        return (pass);
    }

    if (req.url ~ "amasty_label") {
    	return (pass);
    }
if (req.url ~ "stockonwater") {
	return (pass);
}
	if (req.url ~ "/feed") {
		return (pass);
	}

    #if (req.url ~ "\.(jpg|jpeg|png|js|css)$") {
    #    return (pass);
    #}

    # normalize url in case of leading HTTP scheme and domain
    set req.url = regsub(req.url, "^http[s]?://", "");

    # collect all cookies
    std.collect(req.http.Cookie);

    # Compression filter. See https://www.varnish-cache.org/trac/wiki/FAQ/Compression
    if (req.http.Accept-Encoding) {
        if (req.url ~ "\.(gz|tgz|bz2|tbz|mp3|ogg|swf|flv|png|jpg)$") {
            # No point in compressing these
            unset req.http.Accept-Encoding;
        } elsif (req.http.Accept-Encoding ~ "gzip") {
            set req.http.Accept-Encoding = "gzip";
        } elsif (req.http.Accept-Encoding ~ "deflate" && req.http.user-agent !~ "MSIE") {
            set req.http.Accept-Encoding = "deflate";
        } else {
            # unkown algorithm
            unset req.http.Accept-Encoding;
        }
    }

    # Remove Google gclid parameters to minimize the cache objects
    set req.url = regsuball(req.url,"\?gclid=[^&]+$",""); # strips when QS = "?gclid=AAA"
    set req.url = regsuball(req.url,"\?gclid=[^&]+&","?"); # strips when QS = "?gclid=AAA&foo=bar"
    set req.url = regsuball(req.url,"&gclid=[^&]+",""); # strips when QS = "?foo=bar&gclid=AAA" or QS = "?foo=bar&gclid=AAA&bar=baz"

	if (req.url ~ "(\?|&)(gclid|cx|ie|cof|siteurl|zanpid|origin|mc_[a-z]+|utm_[a-z]+)=") {
    set req.url = regsuball(req.url, "(gclid|cx|ie|goal|cof|siteurl|zanpid|origin|mc_[a-z]+|utm_[a-z]+)=[-_A-z0-9+()%.]+&?", "");
    set req.url = regsub(req.url, "[?|&]+$", "");
}

    # static files are always cacheable. remove SSL flag and cookie
        if (req.url ~ "^/(pub/)?(media|static)/.*\.(ico|css|js|jpg|jpeg|png|gif|tiff|bmp|mp3|ogg|svg|swf|woff|woff2|eot|ttf|otf)$") {
        unset req.http.Https;
        unset req.http.X-Forwarded-Proto;
        unset req.http.Cookie;
    }

    return (hash);
}

sub vcl_hash {
    if (req.http.cookie ~ "X-Magento-Vary=") {
        hash_data(regsub(req.http.cookie, "^.*?X-Magento-Vary=([^;]+);*.*$", "\1"));
    }

    # For multi site configurations to not cache each other's content
    if (req.http.host) {
        hash_data(req.http.host);
    } else {
        hash_data(server.ip);
    }

    # To make sure http users don't see ssl warning
    if (req.http.X-Forwarded-Proto) {
        hash_data(req.http.X-Forwarded-Proto);
    }

	if (req.url ~ "/en") {
        hash_data("en");
    }

    if (req.url ~ "/de") {
        hash_data("de");
    }

    if (req.url ~ "/nl") {
        hash_data("nl");
    }

    if (req.url ~ "/se") {
        hash_data("se");
    }

    if (req.url ~ "/it") {
        hash_data("it");
    }

    if (req.url ~ "/no") {
        hash_data("no");
    }

    if (req.url ~ "/es") {
        hash_data("es");
    }

}

sub vcl_backend_response {
    if (beresp.http.content-type ~ "text") {
        set beresp.do_esi = true;
    }

    if (bereq.url ~ "\.js$" || beresp.http.content-type ~ "text") {
        set beresp.do_gzip = true;
    }

    # cache only successfully responses and 404s
    if (beresp.status != 200 && beresp.status != 404) {
        set beresp.ttl = 0s;
        set beresp.uncacheable = true;
        return (deliver);
    } elsif (beresp.http.Cache-Control ~ "private") {
        set beresp.uncacheable = true;
        set beresp.ttl =  86400s;
        return (deliver);
    }

    if (beresp.http.X-Magento-Debug) {
        set beresp.http.X-Magento-Cache-Control = beresp.http.Cache-Control;
    }

    # validate if we need to cache it and prevent from setting cookie
    # images, css and js are cacheable by default so we have to remove cookie also
    if (beresp.ttl > 0s && (bereq.method == "GET" || bereq.method == "HEAD")) {
        unset beresp.http.set-cookie;
        if (bereq.url !~ "\.(ico|css|js|jpg|jpeg|png|gif|tiff|bmp|gz|tgz|bz2|tbz|mp3|ogg|svg|swf|woff|woff2|eot|ttf|otf)(\?|$)") {
            set beresp.http.Pragma = "no-cache";
            set beresp.http.Expires = "-1";
            set beresp.http.Cache-Control = "no-store, no-cache, must-revalidate, max-age=0";
            set beresp.grace = 1m;
        }
    }

   # If page is not cacheable then bypass varnish for 2 minutes as Hit-For-Pass
   if (beresp.ttl <= 0s ||
        beresp.http.Surrogate-control ~ "no-store" ||
        (!beresp.http.Surrogate-Control && beresp.http.Vary == "*")) {
        # Mark as Hit-For-Pass for the next 2 minutes
        set beresp.ttl = 120s;
        set beresp.uncacheable = true;
    }
    return (deliver);
}

sub vcl_deliver {
    if (resp.http.X-Magento-Debug) {
        if (resp.http.x-varnish ~ " ") {
            set resp.http.X-Magento-Cache-Debug = "HIT";
        } else {
            set resp.http.X-Magento-Cache-Debug = "MISS";
        }
    } else {
        unset resp.http.Age;
    }

if (obj.hits > 0) { # Add debug header to see if it's a HIT/MISS and the number of hits, disable when not needed
    set resp.http.X-Cache = "HIT";
    set resp.http.hits = obj.hits;
  } else {
    set resp.http.X-Cache = "MISS";
  }
    set resp.http.X-Country = req.http.X-Country;
    unset resp.http.X-Magento-Debug;
    #unset resp.http.X-Magento-Tags;
    unset resp.http.X-Powered-By;
    unset resp.http.Server;
    #unset resp.http.X-Varnish;
    unset resp.http.Via;
    unset resp.http.Link;
}
