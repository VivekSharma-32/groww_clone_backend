require("dotenv").config();
require("express-async-errors");

const express = require("express"); //import
const app = express(); //invoking
app.use(express.json());
// middlewares
const errorHandlerMiddleware = require("./middleware/error-handler");
const authenticateUser = require("./middleware/authentication");
const notFoundMiddleware = require("./middleware/not-found");

// routers
const authRouter = require("./routes/auth");
const stockRouter = require("./routes/stocks");

const connectDB = require("./config/connect");
app.get("/", (req, res) => {
  // req - getting something from the client

  //res -> sending back response to the client
  return res.json({
    success: true,
    message: "Hit GET API",
  });
});

app.use("/auth", authRouter);
app.use("/stocks", authenticateUser, stockRouter);

app.use(notFoundMiddleware);
app.use(errorHandlerMiddleware);

const port = process.env.PORT || 4000;

const start = async () => {
  try {
    await connectDB(process.env.MONGO_URL);
    app.listen(port, () => {
      console.log(`Server is listening on PORT: ${port}...`);
    });
  } catch (error) {
    console.log(error);
  }
};

start();
