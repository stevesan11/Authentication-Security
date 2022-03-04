//jshint esversion:6
require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");

app.use(session({ secret: "Our little secret.", resave: false, saveUninitialized: false }));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
	email: String,
	password: String,
	googleId: String,
	secret: String,
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function (user, done) {
	done(null, user);
});

passport.deserializeUser(function (user, done) {
	done(null, user);
});

passport.use(
	new GoogleStrategy(
		{
			clientID: process.env.CLIENT_ID,
			clientSecret: process.env.CLIENT_SECRET,
			callbackURL: "http://localhost:3000/auth/google/secrets",
		},
		function (accessToken, refreshToken, profile, cb) {
			User.findOrCreate({ googleId: profile.id }, function (err, user) {
				return cb(err, user);
			});
		}
	)
);

app.get("/", function (req, res) {
	res.render("home");
});
app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));
app.get(
	"/auth/google/secrets",
	passport.authenticate("google", { failureRedirect: "/login" }),
	function (req, res) {
		// Successful authentication, redirect home.
		res.redirect("/secrets");
	}
);
app.get("/login", function (req, res) {
	res.render("login");
});
app.get("/register", function (req, res) {
	res.render("register");
});
app.get("/secrets", function (req, res) {
	if (req.isAuthenticated()) {
		User.find({ secret: { $ne: null } }, function (err, foundUsers) {
			if (err) {
				console.log(err);
			} else {
				if (foundUsers) {
					res.render("secrets", { usersWithSecret: foundUsers });
				}
			}
		});
	} else {
		res.redirect("/login");
	}
});
app.get("/logout", function (req, res) {
	req.logOut();
	res.redirect("/");
});
app.get("/submit", function (req, res) {
	if (req.isAuthenticated()) {
		res.render("submit");
	} else {
		res.redirect("/login");
	}
});

app.post("/register", function (req, res) {
	User.register({ username: req.body.username }, req.body.password, function (err, user) {
		if (err) {
			console.log(err);
			res.redirect("/register");
		} else {
			passport.authenticate("local")(req, res, function () {
				res.redirect("/secrets");
			});
		}
	});
});
app.post("/login", function (req, res) {
	const user = new User({
		username: req.body.username,
		password: req.body.password,
	});
	req.login(user, function (err) {
		if (err) {
			console.log(err);
		} else {
			passport.authenticate("local")(req, res, function () {
				res.redirect("/secrets");
			});
		}
	});
});
app.post("/submit", function (req, res) {
	const submittedSecret = req.body.secret;
	console.log(submittedSecret);
	console.log(req.user);
	User.findByIdAndUpdate({ _id: req.user._id }, { secret: submittedSecret }, function (err) {
		if (!err) {
			res.redirect("/secrets");
		} else {
			console.log(err);
		}
	});
});

app.listen(3000, function (req, res) {
	console.log("Successfuly runnnig server on port 3000");
});
