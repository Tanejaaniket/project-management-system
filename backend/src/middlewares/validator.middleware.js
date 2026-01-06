import { validationResult } from "express-validator";
import { ApiError } from "../utils/apiError.js";

export const validate = (req, res, next) => {
  const errors = validationResult(req); //* These errors are collected by function ran before this middleware
  if (errors.isEmpty()) {
    return next();
  }
  const extractedErrors = [];
  errors.array().map((err) => extractedErrors.push({ [err.path]: err.msg }));
  console.log(extractedErrors)
  throw new ApiError(422,`Recieved data is not valid` ,extractedErrors);
};
