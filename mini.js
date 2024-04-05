// Copyright (c) 2017 Synopsys, Inc. All rights reserved worldwide.
'use strict';

function testsource()
{
    return location.hash;
}

function test1() {
    document.cookie = testsource(); //#defect#SA.COOKIE_INJECTION
}

function testsource3()
{
    return document.URL;
}

function test3() {
    document.writeln(testsource3()); //#defect#SA.DOM_XSS
}

var express = require('express')
var helmet = require('helmet')
var _ = require('lodash')

app.use(helmet.xssFilter({setOnOldIE : true})); //#defect#ENABLED_XSS_FILTER##filter_older_ie

function test4() {
    let express = require('express')();
    express.get("/path", (req, resp) => {
        var taintedURL = req.get("url");
        resp.redirect(taintedURL); //#defect#SA.OPEN_REDIRECT
    });
}


function test5() {
    require('crypto').createCipher("AES192", "K_E_Y"); //#defect#SA.HARDCODED_CREDENTIALS
}


function test6() {
    var req = new XMLHttpRequest("whatever");
    req.setRequestHeader(testsource()); //#defect#SA.HEADER_INJECTION
}


function test8() {
    var x = "http://www.evil.org";
    var iframe = document.createElement('iframe');
    iframe.setAttribute('src', x); //#defect#SA.MISSING_IFRAME_SANDBOX
}

function testsource9()
{
    var server = require('net').createServer();
    var taint = server;
    return taint;
}

function test9() {
    let mongo = require('mongodb');
    let db = new mongo.Db();
    var collection = db.collection("some_collection");
    collection.find( { "$where": testsource9() } ); //#defect#SA.NOSQL_QUERY_INJECTION
}


function test10() {
    let cp = require("child_process");
    foo.shell = testsource9();
    cp.fork(foo, args, foo); //#defect#SA.OS_CMD_INJECTION
}

var app = express(); //#defect#X_POWERED_BY_ENABLED##x_powered_by_http_header

app.get("/",
		 function run(req, res, next) { // Defect here.
		 const file = req.query.file;
		 const data = new Date() + " : " + req.query.data;
		 require("fs").appendFile(//#defect#SA.PATH_MANIPULATION
		 file, // attacker-controlled data used to determine file name
		 data,
		 (err) => {
		 console.log(`Append to '${file}' ` +
		 (err ? `failed: ${err}` : 'succeeded.'));
		 });
		 res.send("Done");
		 });
app.listen(1337, function() {
	 console.log("Express listening...");
});

function test11() {
    testresponse.end(testsource9()); //#defect#SA.XSS
}

//define new whitelist regex
//assign whitelist to aHrefSanitizationWhitelist
angular.module('includeExample', ['ngSanitize']).config(function ($compileProvider) {
    $compileProvider.aHrefSanitizationWhitelist(/(.*)/);//#defect#PERMISSIVE_WHITELIST##wildcard
});

function notMinified(){
    console.log("Algorithm oh Algorithm, we are not minified, please don't detect us as minified");
}

function test13() {
    var safeSrc = _.escapeRegExp(testsource());  //attempted FIX, sqr
    let re = new RegExp(safeSrc); //attempted FIX, sqr
    //let re = new RegExp(testsource());
}

function test14() {
    var crypto = require('crypto');
    var cipher = crypto.createCipher('des-abcdefgh', config.pwd); //#defect#SA.RISKY_CRYPTO
}


function test15() {
    eval(testsource9()); //#defect#SA.SCRIPT_CODE_INJECTION
}


function test17() {
    let password = "P_A_S_S_W_O_R_D";
    console.log(password); //#defect#SA.SENSITIVE_DATA_LEAK
}


function test18() {
    //let query = "SELECT * FROM " + testsource9() + " WHERE col=1"; //#defect#SA.SQLI
    let query = "SELECT * FROM ? WHERE col=1, [testsource9()]" //attempted FIX, sqr
    return query;
}

function do_nothing(event) { } //#defect#SA.UNCHECKED_ORIGIN

function test19() {
    window.onmessage = do_nothing;
}

function test20(message) {
    postMessage(message, "*"); //#defect#SA.UNRESTRICTED_MESSAGE_TARGET
}

const Path = require('path');
const Hapi = require('hapi');
const Inert = require('inert');

const server2 = new Hapi.Server({
    connections: {
        routes: {
            files: {
                relativeTo: Path.join(__dirname, 'public')
            }
        }
    }
});
server2.connection({ port: 3000 });

server2.register(Inert, () => {});

server2.route({
    method: 'GET',
    path: '/{param*}',
    handler: {
        directory: {
            path: '.',
            redirectToSlash: true,
            index: true,
            listing: true //#defect#EXPOSED_DIRECTORY_LISTING##directory_listing
        }
    }
});


const server3 = new hapi.Server();

server3.connection({
  host: 'localhost',
  address: '127.0.0.1',
  port: 8000,
});

server3.register({
  register: require('hapi-server-session'),
  options: {
    expiresIn: 1900000, //#defect#EXTENDED_SESSION_TIMEOUT##extended_duration
  },
}, function (err) { if (err) { throw err; } });


//helmet version 3.0.0 and later
app.use(helmet.hsts({
    maxAge: 10886399, //#defect#HSTS_SHORT_MAX_AGE##hsts_max_age
    includeSubDomains: true
}));


var jwt = require('jsonwebtoken');
var cookieParser = require('cookie-parser')
var port = 3000;

var user = {
    username: 'foo',
    password: 'bar'
};

var tokenSettings = {
    alg: 'HS256'
};

app.use(cookieParser())

app.get('/', function(req, res) {
        res.send('hey there');
    });

app.get('/login', function(req, res) {
    if (req.query.username == user.username &&
        req.query.password == user.password) {
            var token = jwt.sign(user, secret, {
                expiresIn: '5m',
                algorithm: 'HS256' //changing to algorithm, jacks triggers had it wrong with 'alg'
            });
            res.cookie('token', token, {});
            res.send('you should have a cookie');
        } else {
            res.send('bad login');
        }
});

app.get('/test', function (req, res) {
    if (req.cookies.token) {
        jwt.verify(req.cookies.token, 'test4',
            {
                ignoreExpiration: true, //#defect#JWT_EXPIRATION_TIME_IGNORED##expires_in //#jacks#TR-JAVASCRIPT-EXPRESS-JWT-IGNORE-TIME
                algorithms: ['HS256']
            }, function (err, token) {
                res.json(token);
            });
    } else {
        res.send('no token');
    }
});


var expSess = require("express-session"); //#defect#MISSING_SESSION_SECURITY##express

var sess = {
  secret: 'keyboard cat',
  key: "sessionId",
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: true
  }
};


var Blankie = require('blankie');
var Scooter = require('scooter');

server.connection({
  port:port
});

server2.connection({ port: 3000 });
server2.register([{
  register: Inert,
  options: {}
  },{
  register: Scooter,
  options: {}
  },{
  register: Blankie,
  options: {scriptSrc: 'self'}
  }],
  function (err) {
  if (err) {
      throw err;
  }
});


server.register([{//#defect#NON_CONFIGURED_SSL##database
	  register: require('hapi-session-mongo'),
	  options: {  
	    ip: '192.168.0.1',
	    db: 'user',
	    name: 'sessions',
	    pwd: 'shhh i am secret'
	  }
	}]);

server.register([
	  {
	    register: require('crumb'),
	    options: {
	      cookieOptions: {
	        isSecure: true
	      },
	      key: 'X-CSRF-Token' //#defect#UNSAFE_CRUMB_COOKIE##unsafe_key //#jacks#TR-JAVASCRIPT-HAPI-CRUMB-XCSRF
	    }
	  },{
	    register: Inert,
	    options: {}
	  },{
	    register: Scooter,
	    options: {}
	  },{
	    register: Blankie,
	    options: {scriptSrc: 'self'}
	  }
	], function (err) {
	  if (err) {
	    throw err;
	  }
	});

app.get('/test9', function (req, res) {
  if (req.cookies.token) {
    jwt.verify(req.cookies.token, 'test4', {algorithms: ['none']}, function (err, token) { //#defect#UNPROTECTED_JWT_TOKEN##json_web_token
      res.json(token);
    });
  } else {
    res.send('no token');
  }
});

function newFunc1() {
    let query = "SELECT * FROM " + testsource9() + " WHERE col=1"; //#defect#SA.SQLI
    //let query = "SELECT * FROM ? WHERE col=1, [testsource9()]" //attempted FIX, sqr
    return query;
}
