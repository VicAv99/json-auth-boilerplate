import bodyParser from 'body-parser';
import fs from 'fs';
import { create, defaults, router as _router } from 'json-server';
import jwt from 'jsonwebtoken';

const server = create();
const router = _router("server/db.json");
const users = JSON.parse(fs.readFileSync("server/users.json", "UTF-8")).users;
const middlewares = [defaults(), bodyParser.json()];
const port = process.env.PORT || 3000;

// JWT
const SECRET_KEY = "123456789";
const expiresIn = "1h";

// Apply middlewares
server.use(...middlewares);

// Create token from payload
const createToken = (payload) => {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
};

// Verify token
const verifyToken = (token) => {
  return jwt.verify(token, SECRET_KEY, (err, decode) =>
    decode !== undefined ? decode : err
  );
};

// Check if user in DB
const isAuthenticated = ({ email, username, password }) => {
  return (
    users.findIndex((user) => {
      return (
        user.email === email ||
        (user.username === username && user.password === password)
      );
    }) !== -1
  );
};

// login endpoint
server.post("/auth/login", (req, res) => {
  const { email, username, password } = req.body;

  if (isAuthenticated({ email, username, password }) === false) {
    const status = 401;
    const message = "Incorrect email or password";

    res.status(status).json({ status, message });
    return;
  }
  const userRole = users.find((u) => u.email === email).role;
  const access_token = createToken({
    email,
    username,
    password,
    role: userRole,
  });

  res.status(200).json({ access_token });
});

// Verify bearer token
server.use(/^(?!\/auth).*$/, (req, res, next) => {
  if (
    req.headers.authorization === undefined ||
    req.headers.authorization.split(" ")[0] !== "Bearer"
  ) {
    const status = 401;
    const message = "Bad authorization header";

    res.status(status).json({ status, message });
    return;
  }
  try {
    verifyToken(req.headers.authorization.split(" ")[1]);
    next();
  } catch (err) {
    const status = 401;
    const message = "Error: access_token is not valid";

    res.status(status).json({ status, message });
  }
});

server.use(router);

server.listen(port, () => console.log("JSON server is running on port:", port));
