//* For data in body
import { body } from "express-validator";


//* Runs validation on the data of body, .withMessage() returns message for the previous validation and .not() negates result of next validation
export const registerUserValidation = () => {
  return [
    body("email")
      .trim()
      .notEmpty()
      .withMessage("Email is required")
      .isEmail()
      .withMessage("This is not a valid email"),
    body("username")
      .trim()
      .notEmpty()
      .withMessage("Username is required")
      .isAlphanumeric()
      .withMessage("Username must not contain any special symbols")
      .isLowercase()
      .withMessage("Username must be in lowercase")
      .isLength({ min: 3, max: 10 })
      .withMessage("Username must be between 3 to 10 characters long"),
    body("password")
      .trim()
      .notEmpty()
      .withMessage("Password is required")
      .isStrongPassword({
        minLength: 8,
        minUppercase: 1,
        minSymbols: 1,
        minNumbers: 1,
      })
      .withMessage(
        "Password must be atleast 8 characters long and must contain atleast 1 uppercase, atleast 1 special symbol, atleast 1 number"
      ),
  ];
};
