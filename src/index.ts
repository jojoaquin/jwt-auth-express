import express, { NextFunction, Request, Response } from "express";
import dotenv from "dotenv";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import { verify } from "jsonwebtoken";
import cookieParser from "cookie-parser";
import { createToken } from "./createToken";

dotenv.config();
const app = express();

app.use(express.json());
app.use(cookieParser());

const prisma = new PrismaClient();

app.get("/", (_, res: Response) => {
  res.send("Hello world");
});

interface CustomRequest extends Request {
  userId?: number;
}

const accessValidation = async (
  req: CustomRequest,
  res: Response,
  next: NextFunction
) => {
  const refreshToken = req.cookies["refresh-token"];
  const accessToken = req.cookies["access-token"];

  if (!refreshToken && !accessToken) {
    return res.status(401).json({
      message: "Refresh token and access token is not provided",
    });
  }

  if (!refreshToken) {
    return res.status(401).json({
      message: "Refresh token is not provided",
    });
  }

  let data;

  try {
    data = verify(refreshToken, process.env.REFRESH_TOKEN_SECRET!) as any;
    req.userId = data.userId;
  } catch (e) {
    return res.json({
      message: "Refresh token is expired",
    });
  }

  if (!accessToken) {
    const user = await prisma.users.findUnique({ where: { id: data.userId } });
    const tokens = createToken(user!);

    res.cookie("access-token", tokens.accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });

    res.cookie("refresh-token", tokens.refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
    });

    return next();
  }

  try {
    const data = verify(accessToken, process.env.ACCESS_TOKEN_SECRET!) as any;
    req.userId = data.userId;
    return next();
  } catch {}
};

app.post("/register", async (req: Request, res: Response) => {
  const request = req.body;
  const password = await bcrypt.hash(request.password, 11);
  const user = await prisma.users.create({
    data: {
      name: request.name,
      email: request.email,
      password,
      address: request.address,
    },
  });

  return res.json(user);
});

app.post("/login", async (req: Request, res: Response) => {
  const { email, password } = req.body;
  const user = await prisma.users.findUnique({
    where: {
      email,
    },
  });

  if (!user) {
    return res.status(404).json({
      message: "User is not found",
    });
  }

  const isPassValid = await bcrypt.compare(password, user.password!);

  if (!isPassValid) {
    return res.status(403).json({
      message: "Email or password is wrong",
    });
  }

  const { accessToken, refreshToken } = createToken(user);

  res.cookie("access-token", accessToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });

  res.cookie("refresh-token", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
  });

  return res.json({
    data: {
      id: user.id,
      name: user.name,
      address: user.address,
    },
  });
});

app.get("/me", accessValidation, async (req: CustomRequest, res: Response) => {
  const userId = req.userId;
  const user = await prisma.users.findUnique({ where: { id: userId } });
  return res.json(user);
});

app.listen(process.env.PORT, () => {
  console.log("🚀 Server is running in http://localhost:3000");
});
