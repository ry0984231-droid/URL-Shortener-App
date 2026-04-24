require("dotenv").config();
const express = require("express");
const path = require("path");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const shortid = require("shortid");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");


const app = express();
const PORT = process.env.PORT;


// mongoose
//     .connect("mongodb://127.0.0.1:27017/url-shortener")
//     .then(() => console.log("MongoDB Connected"))
//     .catch((err) => console.log(err));
mongoose.connect(process.env.MONGO_URL);


app.set("view engine", "ejs");
app.set("views", path.resolve("./views"));

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());


// const secret = "RajatYadav@$";
const secret = process.env.JWT_SECRET;


function setUserSession(user) {
    return jwt.sign(
        {
            _id: user._id,
            email: user.email,
        },
        secret
    );
}

function getUserFromSession(token) {
    try {
        if (!token) return null;
        return jwt.verify(token, secret);
    } catch {
        return null;
    }
}




function checkauth(req, res, next) {
    const token = req.cookies.uid;
    const user = getUserFromSession(token);
    req.user = user;
    next();
}

// Protected routes
function restrictTologedinUserOnly(req, res, next) {
    const token = req.cookies.uid;

    if (!token) return res.redirect("/Login");

    const user = getUserFromSession(token);

    if (!user) return res.redirect("/Login");

    req.user = user;
    next();
}



const urlSchema = new mongoose.Schema(
    {
        shortId: {
            type: String,
            required: true,
            unique: true,
        },
        redirecturl: {
            type: String,
            required: true,
        },
        visitHistory: [
            {
                timestamp: { type: Date, default: Date.now },
            },
        ],
        createdby: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "user",
        },
    },
    { timestamps: true }
);

const URL = mongoose.model("url", urlSchema);

const userSchema = new mongoose.Schema(
    {
        user_name: {
            type: String,
            required: true,
        },
        email: {
            type: String,
            required: true,
            unique: true,
        },
        password: {
            type: String,
            required: true,
        },
    },
    { timestamps: true }
);

const User = mongoose.model("user", userSchema);




app.get("/", checkauth, async (req, res) => {
    if (!req.user) return res.redirect("/Login");

    const allUrls = await URL.find({
        createdby: req.user._id,
    });

    res.render("home", { urls: allUrls });
});


app.get("/signup", (req, res) => {
    res.render("signup");
});


app.get("/Login", (req, res) => {
    res.render("loginup");
});

app.post("/signup", async (req, res) => {
    const { user_name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
        return res.send("User already exists");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
        user_name,
        email,
        password: hashedPassword,
    });

    res.redirect("/Login");
});


app.post("/loginup", async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
        return res.status(401).send("Invalid email or password");
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
        return res.status(401).send("Invalid email or password");
    }

    const token = setUserSession(user);

    res.cookie("uid", token, {
        httpOnly: true,
    });

    res.redirect("/");
});



app.get("/logout", (req, res) => {
    res.clearCookie("uid");
    res.redirect("/Login");
});


app.post("/url", restrictTologedinUserOnly, async (req, res) => {
    const body = req.body;

    if (!body.url) {
        return res.status(400).send("URL is required");
    }

    const shortURL = shortid();

    await URL.create({
        shortId: shortURL,
        redirecturl: body.url,
        visitHistory: [],
        createdby: req.user._id,
    });

    const allUrls = await URL.find({
        createdby: req.user._id,
    });

    res.render("home", {
        id: shortURL,
        urls: allUrls,
    });
});


app.get("/analytics/:shortId", async (req, res) => {
    const result = await URL.findOne({
        shortId: req.params.shortId,
    });

    if (!result) {
        return res.status(404).send("Not found");
    }

    res.json({
        totalClicks: result.visitHistory.length,
        visitHistory: result.visitHistory,
    });
});


app.get("/:shortId", async (req, res) => {
    const entry = await URL.findOneAndUpdate(
        { shortId: req.params.shortId },
        {
            $push: {
                visitHistory: {
                    timestamp: new Date(),
                },
            },
        }
    );

    if (!entry) {
        return res.status(404).send("Short URL not found");
    }

    res.redirect(entry.redirecturl);
});


app.listen(PORT, () =>
    console.log(`Server started at port ${PORT}`)
);