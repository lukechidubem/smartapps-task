import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import otpGenerator from 'otp-generator';
import multer from 'multer';
import sharp from 'sharp';
import AppError from '../utils/appError';
import { User } from '../models/userModel';
import catchAsync from '../utils/catchAsync';
import { otpMail } from '../emailTemplates/otp';
import filterObject from '../utils/filterObject';
import mailService = require('../services/mailer');
import { welcomeMail } from '../emailTemplates/welcome';
import cloudinary from '../utils/cloudinary';

const signToken = (id: string): string => {
  return jwt.sign({ id }, process.env.JWT_SECRET as string, {
    expiresIn: process.env.JWT_EXPIRES_IN as string,
  });
};

const createSendToken = (
  user: any,
  statusCode: number,
  message: string,
  req: Request,
  res: Response
): void => {
  const token = signToken(user._id);

  res.cookie('jwt', token, {
    expires: new Date(
      Date.now() +
        Number(process.env.JWT_COOKIE_EXPIRES_IN) * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
    secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
  });

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user,
    },
    message,
  });
};

// ============================ File Upload ==========================

const multerStorage = multer.memoryStorage();

const multerFilter = (
  req: Request,
  file: Express.Multer.File,
  cb: (error: Error | null, acceptFile: boolean) => void
) => {
  if (file.mimetype.startsWith('image')) {
    cb(null, true);
  } else {
    cb(new AppError('Not an image! Please upload only images.', 400), false);
  }
};

const upload = multer({
  storage: multerStorage,
  fileFilter: multerFilter as any,
});

const uploadUserPhoto = upload.single('photo');

const resizeUserPhoto = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    if (!req.file) {
      return next(new AppError('Please upload an image file', 400));
    }

    req.file.filename = `user-${Math.random()}-${Date.now()}.jpeg`;

    await sharp(req.file.buffer)
      .resize(500, 500)
      .toFormat('jpeg')
      .jpeg({ quality: 90 })
      .toFile(`public/img/${req.file.filename}`);

    next();
  }
);

// ============================ SignUp ==========================
const signup = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email } = req.body;

    if (!req.file) {
      return next(new AppError('Please upload an image file', 400));
    }

    const name = req.body.fileName;

    const fileName = `${name}-${Date.now()}`;

    const result = await cloudinary.uploader.upload(
      `public/img/${req.file.filename}`,
      {
        folder: `my-folder/${fileName}`,
      }
    );

    const filteredBody = filterObject(
      req.body,
      'firstName',
      'lastName',
      'email',
      'password',
      'photo'
    );

    filteredBody.photo = result.secure_url;

    fs.unlink(`public/img/${req.file.filename}`, (err: any) => {
      if (err) console.error(err);
    });

    // check if verified user with the email is already registered
    const userExist = await User.findOne({ email: email });

    if (userExist && userExist.verified) {
      return next(
        new AppError('Email already registered, try logging in', 400)
      );
    } else if (userExist) {
      await User.findOneAndUpdate({ email: email }, filteredBody, {
        new: true,
        validateModifiedOnly: true,
      });

      (req as any).userId = userExist._id;
      next();
    } else {
      const newUser = await User.create(filteredBody);

      (req as any).userId = newUser._id;
      next();
    }
  }
);

// ============================ Sendin OTP for Email verification ==========================
const sendOTP = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const { userId } = req as any;

    const newOtp = otpGenerator.generate(6, {
      lowerCaseAlphabets: false,
      upperCaseAlphabets: false,
      specialChars: false,
    });

    const otpExpiresTime = Date.now() + 10 * 60 * 1000;

    const user = await User.findByIdAndUpdate(userId, {
      otpExpiresTime,
    });

    if (!user) {
      return next(new Error('User not found'));
    }

    user.otp = newOtp.toString();

    await user.save({ validateBeforeSave: true });

    // Sending the OTP to the user's email address
    const url = `${req.protocol}://${req.get('host')}/verify`;

    mailService.sendMail({
      sender: 'lukechidubem@gmail.com',
      to: user.email,
      subject: 'OTP for email verification',
      html: otpMail(user.firstName, newOtp),
      attachments: [],
    });

    res.status(200).json({
      status: 'success',
      otp: newOtp,
      message: 'OTP sent successfully for email verification',
    });
  }
);

// ============================ Email verification and Welcome message ==========================
const verifyEmail = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email, otp } = req.body;

    const user = await User.findOne({
      email,
      otpExpiresTime: { $gt: Date.now() },
    });

    if (!user) {
      return next(new AppError('Invalid Email or Expired OTP', 401));
    }

    if (user.verified) {
      return next(new AppError('Email is already verified', 401));
    }

    if (!(await user.correctOTP(otp, user.otp))) {
      return next(new AppError('Incorrect OTP', 401));
    }

    // Correct OTP
    user.verified = true;
    user.otp = undefined as any;
    user.otpExpiresTime = undefined as any;

    await user.save({
      // new: true,
      validateModifiedOnly: true,
    });

    createSendToken(user, 200, 'Email verification is successful', req, res);

    const url = `${req.protocol}://${req.get('host')}`;

    mailService.sendMail({
      sender: 'lukechidubem@gmail.com',
      to: user.email,
      subject: 'Welcome to SmartApps',
      html: welcomeMail(user.firstName, url),
      attachments: [],
    });
  }
);

// ============================ User Login ==========================
const login = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email, password } = req.body;

    // 1) Check if email and password exist
    if (!email || !password) {
      return next(new AppError('Please provide email and password!', 400));
    }

    // 2) Check if user exists && password is correct
    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.correctPassword(password, user.password))) {
      return next(new AppError('Incorrect email or password', 401));
    }

    if (!user.verified) {
      return next(new AppError('Email not verified', 401));
    }
    // 3) If everything is okay, send token to client
    createSendToken(user, 200, 'User login successful', req, res);
  }
);

export default {
  signup,
  sendOTP,
  verifyEmail,
  login,
  uploadUserPhoto,
  resizeUserPhoto,
};
