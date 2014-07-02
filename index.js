var config = require('./config');
var http = require('http');
var url = require('url');
var LdapAuth = require('ldapauth');
var authentication = require('basic-authentication')({functions: true});
var crypto = require('crypto');

LdapAuth.prototype.checkGroupMembership = function (userDn, group, searchBase, callback) {
    var self = this;
    self._adminClient.search(searchBase,
                             { filter: 'cn=' + group, scope: 'sub' },
                             function (err, result) {
        if (err)
            return callback(err);
        var items = [];
        result.on('searchEntry', function (entry) {
            items.push(entry.object);
        });
        result.on('error', function (err) {
            self.log && self.log.trace('ldap authenticate: search error event: %s', err);
            return callback(err);
        });
        result.on('end', function (result) {
            if (result.status !== 0) {
                var err = 'non-zero status from LDAP search: ' + result.status;
                self.log && self.log.trace('ldap authenticate: %s', err);
                return callback(err);
            }
            switch (items.length) {
            case 0:
                return callback(null, false);
            case 1:
                // console.log(JSON.stringify(items[0]));
                var memberList = items[0].member;
                if (!Array.isArray(memberList))
                    return callback("Group doesn't contain members list!");
                return callback(null, memberList.some(function(memberDn) {
                    return userDn === memberDn;
                }));
            default:
                return callback(format('unexpected number of matches (%s) for "%s" group', items.length, group));
            }
        });
    });                      
}

var logger = {
    getLogger: function (a, b) {
        return { trace: console.log, debug: console.log, info: console.log, warn: console.log, error: console.log  };
    }
};

var getLdapAuth = function () {
    return new LdapAuth({
        url: config.ldap.serverUrl,
        adminDn: config.ldap.adminDn,
        adminPassword: config.ldap.adminPassword,
        searchBase: config.ldap.userSearchBase,
        searchFilter: config.ldap.userSearchFilter,
        verbose: true,
        log4js: logger
    });
};

var nop = function () {};

// working around bugs in ldapauth:
// * userClient is not unbound
// * unbinding doesn't actually close the connection
var cleanup = function(ldapauth) {
    ldapauth.close(function ()  {
        ldapauth._adminClient.socket.end();
    });
    ldapauth._userClient.unbind(function () {
        ldapauth._userClient.socket.end();
    });
};

var cache = {};
var cacheLifetime = 15000;

var cacheKey = function(user, password, group) {
    return crypto.createHash('sha256').update([user, password, group].join('-!-')).digest('base64');
};

var cacheHas = function(key) {
    if (cache[key]) {
        return cache[key].time + cacheLifetime > Date.now();
    }
    return false;
};

var cacheGet = function(key) {
    if (cache[key]) {
        return cache[key].result;
    }
    return false;
};

var cachePut = function(key, allowed) {
    cache[key] = { result: allowed, time: Date.now() };
};

setInterval(function() {
    expired = Object.keys(cache).filter(function (key) {
        return cache[key].time + cacheLifetime < Date.now();
    }).forEach(function (key) {
        delete cache[key];
    });
}, 60*1000);

var server = http.createServer(function(request, response) {
    var auth = authentication(request);
    if (auth === false) {
        response.statusCode = 401;
        response.setHeader('WWW-Authenticate', 'Basic realm="LDAP username/password"');
        return response.end();
    }

    var group = url.parse(request.url).pathname.split('/')[1];
    var ckey = cacheKey(auth.user, auth.password, group);

    if (cacheHas(ckey)) {
        if (cacheGet(ckey)) {
            response.statusCode = 200;
        } else {
            response.statusCode = 401;
            response.setHeader('WWW-Authenticate', 'Basic realm="LDAP username/password"');
        }
        return response.end();
    }

    var ldapauth = getLdapAuth();
    ldapauth.authenticate(auth.user, auth.password, function(err, user) {
        if (err != null) {
            console.log(err);
            response.statusCode = 401;
            response.setHeader('WWW-Authenticate', 'Basic realm="LDAP username/password"');
            response.end();
            cachePut(ckey, false);
            return cleanup(ldapauth);
        }
        if (user && user.uid === auth.user) {
            // console.log(JSON.stringify(user));
            if (!group) {
                response.statusCode = 200;
                response.end();
                cachePut(ckey, true);
                return cleanup(ldapauth);
            }            
            return ldapauth.checkGroupMembership(user.dn, group, config.ldap.groupSearchBase, function(err, isMember) {
                if (err != null) {
                    console.log(err);
                    response.statusCode = 401;
                    response.setHeader('WWW-Authenticate', 'Basic realm="LDAP username/password"');
                    cachePut(ckey, false);
                } else if (!isMember) {
                    response.statusCode = 401;
                    response.setHeader('WWW-Authenticate', 'Basic realm="LDAP username/password"');
                    cachePut(ckey, false);
                } else {
                    response.statusCode = 200;
                    cachePut(ckey, true);
                }
                response.end();
                return cleanup(ldapauth);
            });
        }
        response.statusCode = 401;
        response.setHeader('WWW-Authenticate', 'Basic realm="LDAP username/password"');
        response.end();
        cachePut(ckey, false);
        return cleanup(ldapauth);
    });
});

server.listen(config.http.port);
