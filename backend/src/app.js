import express from "express";
import dotenv from "dotenv";
import cors from "cors";

dotenv.config({
  path: "./.env",
  quiet: true,
});

const app = express();

app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" })); //* Helps reading data from url params, queries etc
app.use(express.static("public")); //* Helps server static content like images
app.use(
  cors({
    origin: process.env.CORS_ORIGIN?.split(",") || "http://localhost:5173",
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTION"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

import healthcheckRoutes from "./routes/healtcheck.routes.js";

app.use("/api/v1/healthcheck", healthcheckRoutes);

export default app;
