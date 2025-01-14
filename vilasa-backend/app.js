const express = require("express");
const app = express();
const errorMiddleware = require("./middleware/error");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const fileUpload = require("express-fileupload"); // Middleware for handling file uploads
const path = require("path");
const cors = require("cors");
const cronSchedule = require('./Schedule');
const listEndpoints = require('express-list-endpoints');
const dotenv = require("dotenv");
dotenv.config({ path: "vilasa-backend/config/config.env" });

// Importing routes
const user = require("./routes/userRoute");
const order = require("./routes/orderRoute");
const product = require("./routes/productRoute");
const payment = require("./routes/paymentRoute");
const chat = require("./routes/chatRoute");
const dyimg = require("./routes/dynamicImageRoutes");
const dyurl = require("./routes/urlRoutes");
const invoice = require("./routes/invoiceRoute");

// Middleware setup
app.use(cookieParser()); // Middleware for parsing cookies
app.use(express.json()); // Middleware for parsing JSON bodies
app.use(bodyParser.json({ limit: "50mb" })); // Middleware for parsing JSON with a size limit
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true })); // Middleware for parsing URL-encoded data with a size limit
app.use(fileUpload()); // Middleware for handling file uploads
app.use(cors()); // Middleware for enabling CORS

// Custom error handling middleware
app.use(errorMiddleware);

// Route setup
app.use("/api/vilasa-v1/product", product); // Product routes
app.use("/api/vilasa-v1/user", user); // User routes
app.use("/api/vilasa-v1/order", order); // Order routes
app.use("/api/vilasa-v1/payment", payment); // Payment routes
app.use("/api/vilasa-v1/chat/v.0.0.1",chat);
app.use("/api/vilasa-v1/db-img/vilasa", dyimg);
app.use("/api/vilasa-v1/db-url/vilasa", dyurl);
app.use("/api/vilasa-v1/order/report",invoice);

// Middleware to expose endpoint list only in development mode

const environment = process.env.NODE_ENV || 'development';

if (environment === 'development') {
  app.get('/api/Secrete/endpoints', (req, res) => {
    console.log('Middleware triggered. Getting endpoints...');
    const endpoints = listEndpoints(app);
    console.log('Endpoints retrieved:', endpoints);
    res.json(endpoints);
  });
}
// Serve static files from the frontend build directory
const __dirname1 = path.resolve();
// app.use(express.static(path.join(__dirname1, "/frontend/build")));

// Serve the React app for any other routes
// app.get("*", (req, res) =>
//   res.sendFile(path.resolve(__dirname1, "frontend", "build", "index.html"))
// );

// Simple middleware for logging each request to the console
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

module.exports = app;
