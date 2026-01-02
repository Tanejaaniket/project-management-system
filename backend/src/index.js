import app from "./app.js";
import { connectDB } from "./db/index.js";

const port = process.env.PORT || 3000;

connectDB()
  .then(() => {
    app.listen(port, () => {
      console.log(`Example app listening on port ${port}`);
    });
  })
  .catch((err) => {
    console.error("Error connecting to server", err);
  });
