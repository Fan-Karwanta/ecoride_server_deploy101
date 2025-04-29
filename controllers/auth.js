import User from "../models/User.js";
import { StatusCodes } from "http-status-codes";
import { BadRequestError, UnauthenticatedError } from "../errors/index.js";
import jwt from "jsonwebtoken";

// Simple test endpoint
export const testAuth = async (req, res) => {
  res.status(StatusCodes.OK).json({ message: "Auth endpoint is working" });
};

// Login with email and password
export const login = async (req, res) => {
  const { email, password, role } = req.body;

  if (!email || !password) {
    throw new BadRequestError("Please provide email and password");
  }

  if (!role || !["customer", "rider"].includes(role)) {
    throw new BadRequestError("Valid role is required (customer or rider)");
  }

  try {
    const user = await User.findOne({ email, role });
    
    if (!user) {
      throw new UnauthenticatedError("Invalid credentials");
    }

    const isPasswordCorrect = await user.comparePassword(password);
    if (!isPasswordCorrect) {
      throw new UnauthenticatedError("Invalid credentials");
    }

    const accessToken = user.createAccessToken();
    const refreshToken = user.createRefreshToken();

    return res.status(StatusCodes.OK).json({
      message: "User logged in successfully",
      user,
      access_token: accessToken,
      refresh_token: refreshToken,
    });
  } catch (error) {
    console.error(error);
    throw error;
  }
};

// Register a new user
export const register = async (req, res) => {
  const { 
    email, 
    password, 
    role, 
    firstName, 
    middleName, 
    lastName, 
    phone, 
    schoolId,
    licenseId,
    sex
  } = req.body;

  if (!email || !password) {
    throw new BadRequestError("Please provide email and password");
  }

  if (!role || !["customer", "rider"].includes(role)) {
    throw new BadRequestError("Valid role is required (customer or rider)");
  }

  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      throw new BadRequestError("Email already in use");
    }

    // Create new user
    const user = new User({
      email,
      password,
      role,
      firstName,
      middleName,
      lastName,
      phone,
      schoolId,
      licenseId,
      sex
    });

    await user.save();

    const accessToken = user.createAccessToken();
    const refreshToken = user.createRefreshToken();

    res.status(StatusCodes.CREATED).json({
      message: "User created successfully",
      user,
      access_token: accessToken,
      refresh_token: refreshToken,
    });
  } catch (error) {
    console.error(error);
    throw error;
  }
};

// Legacy phone-based authentication (keeping for backward compatibility)
export const auth = async (req, res) => {
  const { phone, role } = req.body;

  if (!phone) {
    throw new BadRequestError("Phone number is required");
  }

  if (!role || !["customer", "rider"].includes(role)) {
    throw new BadRequestError("Valid role is required (customer or rider)");
  }

  try {
    let user = await User.findOne({ phone });

    if (user) {
      if (user.role !== role) {
        throw new BadRequestError("Phone number and role do not match");
      }

      const accessToken = user.createAccessToken();
      const refreshToken = user.createRefreshToken();

      return res.status(StatusCodes.OK).json({
        message: "User logged in successfully",
        user,
        access_token: accessToken,
        refresh_token: refreshToken,
      });
    }

    user = new User({
      phone,
      role,
      // Set a temporary email and password for legacy users
      email: `${phone}@temp.ecoride.com`,
      password: Math.random().toString(36).slice(-8) + Math.random().toString(36).slice(-8),
    });

    await user.save();

    const accessToken = user.createAccessToken();
    const refreshToken = user.createRefreshToken();

    res.status(StatusCodes.CREATED).json({
      message: "User created successfully",
      user,
      access_token: accessToken,
      refresh_token: refreshToken,
    });
  } catch (error) {
    console.error(error);
    throw error;
  }
};

export const refreshToken = async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) {
    throw new BadRequestError("Refresh token is required");
  }

  try {
    const payload = jwt.verify(refresh_token, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(payload.id);

    if (!user) {
      throw new UnauthenticatedError("Invalid refresh token");
    }

    const newAccessToken = user.createAccessToken();
    const newRefreshToken = user.createRefreshToken();

    res.status(StatusCodes.OK).json({
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
    });
  } catch (error) {
    console.error(error);
    throw new UnauthenticatedError("Invalid refresh token");
  }
};

// Get user profile information
export const getUserProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    
    if (!user) {
      throw new UnauthenticatedError("User not found");
    }

    res.status(StatusCodes.OK).json({
      user
    });
  } catch (error) {
    console.error(error);
    throw error;
  }
};

// Update user profile information
export const updateUserProfile = async (req, res) => {
  const { firstName, middleName, lastName, phone, schoolId, licenseId, email, sex } = req.body;

  try {
    const user = await User.findById(req.user.id);
    
    if (!user) {
      throw new UnauthenticatedError("User not found");
    }

    // Update fields if provided
    if (firstName) user.firstName = firstName;
    if (middleName !== undefined) user.middleName = middleName;
    if (lastName) user.lastName = lastName;
    if (phone) user.phone = phone;
    if (schoolId !== undefined) user.schoolId = schoolId;
    if (licenseId !== undefined) user.licenseId = licenseId;
    if (sex) user.sex = sex;
    if (email) {
      // Check if email is already in use by another user
      const existingUser = await User.findOne({ email, _id: { $ne: req.user.id } });
      if (existingUser) {
        throw new BadRequestError("Email already in use");
      }
      user.email = email;
    }

    await user.save();

    // Return updated user without password
    const updatedUser = await User.findById(req.user.id).select('-password');

    res.status(StatusCodes.OK).json({
      message: "Profile updated successfully",
      user: updatedUser
    });
  } catch (error) {
    console.error(error);
    throw error;
  }
};
