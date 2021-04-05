const Sequelize = require("sequelize");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const secret = process.env.SECRET;
// supersecrettoken = secretsquirrel

//saltRounds: how many times a pw should hash. Higher #, more secure, more expensive in time.
const saltRounds = 10;

const { STRING } = Sequelize;
const config = {
  logging: false,
};

if (process.env.LOGGING) {
  delete config.logging;
}
const conn = new Sequelize(
  process.env.DATABASE_URL || "postgres://localhost/acme_db",
  config
);

const User = conn.define("user", {
  username: STRING,
  password: STRING,
});

User.byToken = async (token) => {
  try {
    const { userId } = jwt.verify(token, secret);
    const user = await User.findByPk(userId);
    if (user) {
      return user;
    }
    const error = Error("bad credentials");
    error.status = 401;
    throw error;
  } catch (ex) {
    const error = Error("bad credentials");
    error.status = 401;
    throw error;
  }
};

User.beforeCreate(async (user) => {
  const salt = await bcrypt.genSaltSync(saltRounds);
  const hash = await bcrypt.hashSync(user.password, salt);
  user.password = hash;
  // await bcrypt.genSalt(saltRounds, function (err, salt) {
  //   bcrypt.hash(user.password, salt, function (err, hash) {
  //     user.password = hash;
  //     console.log(");
  //   });
  //});
  // console.log("USER", user);
});

User.authenticate = async ({ username, password }) => {
  const user = await User.findOne({
    where: {
      username,
      // password,
    },
  });
  const result = bcrypt.compareSync(password, user.password);

  if (user && result) {
    const token = jwt.sign({ userId: user.id }, secret);
    return token;
  }
  const error = Error("bad credentials");
  error.status = 401;
  throw error;
};

const syncAndSeed = async () => {
  await conn.sync({ force: true });
  const credentials = [
    { username: "lucy", password: "lucy_pw" },
    { username: "moe", password: "moe_pw" },
    { username: "larry", password: "larry_pw" },
  ];
  const [lucy, moe, larry] = await Promise.all(
    credentials.map((credential) => User.create(credential))
  );
  return {
    users: {
      lucy,
      moe,
      larry,
    },
  };
};

module.exports = {
  syncAndSeed,
  models: {
    User,
  },
};
