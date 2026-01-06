import { Router } from "express";
import { registerUser } from "../controllers/auth.controller.js";
import { registerUserValidation } from "../validators/index.js";
import { validate } from "../middlewares/validator.middleware.js";

const router = Router();

router.post("/register", registerUserValidation(), validate, registerUser);

export default router;
