var config = require('./config');
var http = require('http');
var url = require('url');
var LdapAuth = require('ldapauth');
var authentication = require('basic-authentication')({functions: true});

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

var ldapauth = new LdapAuth({
    url: config.ldap.serverUrl,
    adminDn: config.ldap.adminDn,
    adminPassword: config.ldap.adminPassword,
    searchBase: config.ldap.userSearchBase,
    searchFilter: config.ldap.userSearchFilter
});

var server = http.createServer(function(request, response) {
    var auth = authentication(request);
    if (auth === false) {
        response.statusCode = 401;
        response.setHeader('WWW-Authenticate', 'Basic realm="LDAP username/password"');
        return response.end();
    }
    var group = url.parse(request.url).pathname.split('/')[1];
    return ldapauth.authenticate(auth.user, auth.password, function(err, user) {
        if (err != null) {
            console.log(err);
            response.statusCode = 403;
            return response.end();
        }
        if (user && user.uid === auth.user) {
            // console.log(JSON.stringify(user));
            if (!group) {
                response.statusCode = 200;
                return response.end();
            }            
            return ldapauth.checkGroupMembership(user.dn, group, config.ldap.groupSearchBase, function(err, isMember) {
                if (err != null) {
                    console.log(err);
                    response.statusCode = 403;
                } else if (!isMember) {
                    response.statusCode = 403;
                } else {
                    response.statusCode = 200;
                }
                return response.end();
            });
        }
        response.statusCode = 403;
        return response.end();
    });
});

server.listen(config.http.port);
