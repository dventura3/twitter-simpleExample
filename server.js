var port = 3000;
var express = require('express')
  , passport = require('passport')
  , util = require('util')
  , TwitterStrategy = require('passport-twitter').Strategy
  , config = require('./config')
  , user = {}
  , oa
  , twitterAuthn
  , twitterAuthz
  ;

var tweet_operations = {
	  newTweet : "https://api.twitter.com/1.1/statuses/update.json"
	, sendPrivateMessage : "https://api.twitter.com/1.1/direct_messages/new.json"
}

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete Twitter profile is serialized
//   and deserialized.
passport.serializeUser(function(user, done) {
	done(null, user);
});

passport.deserializeUser(function(user, done) {
	done(null, user);
});


//Oauth autentication for Twetter
//"http://"+config.domainName+"/oauthn/twitter/callback",
function initTwitterOauth(){
	var OAuth = require('oauth').OAuth;
	oa = new OAuth( 
					"https://twitter.com/oauth/request_token",
        			"https://twitter.com/oauth/access_token", 
                	config.consumerKey,
                	config.consumerSecret, 
                	"1.0A", 
                	"http://"+config.domainName+"/authz/twitter/callback",
                	"HMAC-SHA1"
                );
}

function postTweet(text_for_tweet, cb){
	oa.post(
		tweet_operations.newTweet,
		user.token, 
		user.tokenSecret,
		{	
			"status" : text_for_tweet
		}, 
		cb
	);
}

function makePrivateMSG(userID, text_for_msg, cb){
	oa.post(
		tweet_operations.sendPrivateMessage,
		user.token, 
		user.tokenSecret,
		{	
			  "screen_name" : userID
			, "text" : text_for_msg
		}, 
		cb
	);
}

twitterAuthn = new TwitterStrategy({
		consumerKey: config.consumerKey,
		consumerSecret: config.consumerSecret,
		//nb: la callback a cui l'utente viene rediretto dopo aver fatto il login è una pagina web
		//definita poco sotto. Cerca: "app.get('/authn/twitter'"
		callbackURL: "http://"+config.domainName+"/authn/twitter/callback" 
	},
	function(token, tokenSecret, profile, done) {
		//come risposta il server di twitter mi da un token che identifica l'utente connesso
		user.token = token;
		user.tokenSecret = tokenSecret;
		user.profile = profile;
		initTwitterOauth();
		done(null, user);
	}
);
twitterAuthn.name = "twitterAuthn";

twitterAuthz = new TwitterStrategy({
		consumerKey: config.consumerKey,
		consumerSecret: config.consumerSecret,
		//nb: la callback a cui l'utente viene rediretto dopo aver fatto il login è una pagina web
		//definita poco sotto. Cerca: "app.get('/authn/twitter'"
		callbackURL: "http://"+config.domainName+"/authz/twitter/callback",
		userAuthorizationURL: 'https://api.twitter.com/oauth/authorize'
	},
	function(token, tokenSecret, profile, done) {
		//come risposta il server di twitter mi da un token che identifica l'utente connesso
		user.token = token;
		user.tokenSecret = tokenSecret;
		user.profile = profile;
		initTwitterOauth();
		done(null, user);
	}
);
twitterAuthz.name = "twitterAuthz";

passport.use(twitterAuthn);
passport.use(twitterAuthz);

//DANIELA
/*
allowCrossDomain = function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.header("Access-Control-Allow-Headers", req.headers["access-control-request-headers"]);
    res.header("Access-Control-Allow-Credentials", "true");
    if ("OPTIONS" == req.method) {
        res.send(200);
    } else {
        next();
    }
}
*/

//server creato!
var app = express.createServer();

app.configure(function() {

	//DANIELA
	//allow all crossDomain request
	/*
	app.use(allowCrossDomain);
	*/

	app.use(express.favicon());
	app.use(express.logger('dev'));
	app.use(express.bodyParser());
	app.use(express.cookieParser());
	app.use(express.methodOverride());
	app.use(express.session({ secret: 'blablabla' }));
	app.use(passport.initialize());
  	app.use(passport.session());
  	app.use(app.router);
	//con l'istruzione sotto diciamo che è possibile visualizzare sul client i file contenuti dentro la directory /public/...
	app.use(express.static(__dirname + '/public'));
});


app.get('/', function(req, res){
	return res.sendfile('index.html');
});

app.get('/success', function(req, res){
	//ridiriggo verso la home!
	res.redirect('/');
	//res.end("Success");
});

app.get('/failure', function(req, res){
	return res.end("Failure");
});

app.get('/login', function(req, res){
	//ridiriggo verso la home!
	res.redirect('/authn/twitter');
});



//****  FOR  twitterAuthn  ****/
// Redirect the user to Twitter for authentication.  When complete, Twitter
// will redirect the user back to the application at
//   /authn/twitter/callback
app.get('/authn/twitter', passport.authenticate('twitterAuthn'));

// Twitter will redirect the user to this URL after approval.  Finish the
// authentication process by attempting to obtain an access token.  If
// access was granted, the user will be logged in.  Otherwise,
// authentication has failed.
app.get('/authn/twitter/callback', passport.authenticate('twitterAuthn', {
									  //successRedirect: '/success'
									  successRedirect: '/'
									, failureRedirect: '/failure' 
								}
));


//****  FOR  twitterAuthz  ****/
app.get('/authz/twitter', passport.authenticate('twitterAuthz'));
app.get('/authz/twitter/callback', passport.authenticate('twitterAuthz', {
									  successRedirect: '/'
									, failureRedirect: '/failure' 
								}
));


//used to send a tweet
app.get('/twitter/tweet', function(req, res){
	var url = require('url').parse(req.url,true);
	var text_for_tweet = url.query.text;

	postTweet(
		text_for_tweet
		, function(error, data) {
			if(error){
				console.log(require('sys').inspect(error));
				res.end('bad stuff happenend');
			}
			else {
				console.log(data);
				res.end('go check your tweet!');
			}
		}
	);
});


//used to send a private message
app.get('/twitter/direct/:sn', function(req, res){
	var url = require('url').parse(req.url,true);
	var text_for_msg = url.query.text;
	var userID = req.params.sn;

	makePrivateMSG(
		userID
		, text_for_msg
		, function(error, data) {
			if(error){
				console.log(require('sys').inspect(error));
				res.end('bad stuff happenend');
			}
			else {
				console.log(data);
				res.end('MSG sent!');
			}
		}
	);
});


app.listen(3741);