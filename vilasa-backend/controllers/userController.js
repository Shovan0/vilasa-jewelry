// Import required modules and dependencies
const User = require('../model/userModel'); // Import user model
const asyncErrorHandler = require('../middleware/asyncErrorHandler'); // Import async error handler middleware
const ErrorHandler = require('../utils/errorHandler'); // Import custom error handler
const sendEmail = require('../utils/sendEmail'); // Import send email utility
const crypto = require('crypto'); // Import crypto module for generating hash
const cloudinary = require('cloudinary'); // Import cloudinary for image upload
const sendJWtToken = require('../utils/JwtToken')

// Register a new user
exports.registerUser = asyncErrorHandler(async (req, res, next) => {
    const { name, email, password, gender, avatar } = req.body;

    // Check if the email is already registered
    const existingUser = await User.findOne({ email });
    if (existingUser) {
        return next(new ErrorHandler('User already exists with this email', 400));
    }

    try {
        // Upload avatar to Cloudinary asynchronously
        const avatarUploadPromise = cloudinary.v2.uploader.upload(avatar, {
            folder: 'avatars',
            width: 150,
            crop: 'scale',
        });

        // Create the new user while avatar upload is in progress
        const newUser = await User.create({
            name,
            email,
            password,
            gender,
        });

        // Wait for avatar upload to complete
        const avatarUpload = await avatarUploadPromise;

        // Update user with avatar details
        newUser.avatar = {
            public_id: avatarUpload.public_id,
            url: avatarUpload.secure_url,
        };
        await newUser.save();

        // Send welcome email to the new user asynchronously
        sendEmail({
            email: newUser.email,
            subject: 'Welcome to Our Platform!',
            message: `Hello ${newUser.name},\n\nWelcome to our platform. We're excited to have you on board!`,
        }).catch(console.error); // Error handling for email sending

        // Send response with JWT token
        sendJWtToken(newUser, 201, res);
    } catch (error) {
        next(error); // Pass any error to error handling middleware
    }
});

// Login user
exports.loginUser = asyncErrorHandler(async (req, res, next) => {
    const { email, password } = req.body;

    // Check if email and password are provided
    if (!email || !password) {
        return next(new ErrorHandler('Please provide email and password', 400)).toJSON();
        
    }

    // Check if the user exists
    const user = await User.findOne({ email }).select('+password');
    if (!user || !(await user.matchPassword(password))) {
        return next(new ErrorHandler('Invalid email or password', 401));
    }

    // Send JWT token to the client
    sendJWtToken(user, 200, res);
});

// Logout user
exports.logoutUser = asyncErrorHandler(async (req, res, next) => {
    // Clear the JWT cookie
    // Generate a new random token
    const newToken = crypto.randomBytes(32).toString('hex');
    res.cookie('token', newToken, {
        expires: new Date(Date.now() + 10 * 1000), // Expire in 10 seconds
        httpOnly: true,
    });

    // Send response
    res.status(200).json({
        success: true,
        message: 'User logged out successfully',
    });
});



// Forgot password - Send reset token
exports.forgotPassword = asyncErrorHandler(async (req, res, next) => {
    const user = await User.findOne({ email: req.body.email });

    // Check if user exists with provided email
    if (!user) {
        return next(new ErrorHandler('User not found with this email', 404));
    }

    // Generate and hash the reset token
    const resetToken = user.getResetPasswordToken();
    await user.save({ validateBeforeSave: false });

    // Create the reset URL
    const resetUrl = `${req.protocol}://${req.get('host')}/api/v1/auth/resetpassword/${resetToken}`;

    // Send the password reset email
    const message = `You are receiving this email because you (or someone else) has requested the reset of a password. Please make a PUT request to: \n\n ${resetUrl}`;

    try {
        await sendEmail({
            email: user.email,
            subject: 'Password reset token',
            message,
        });

        // Send response
        res.status(200).json({
            success: true,
            message: 'Password reset token sent to email',
        });
    } catch (error) {
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;
        await user.save({ validateBeforeSave: false });

        // Handle email sending error
        return next(new ErrorHandler('Email could not be sent', 500));
    }
});

// Reset password
exports.resetPassword = asyncErrorHandler(async (req, res, next) => {
    // Get hashed token
    const resetPasswordToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

    // Find user by reset token
    const user = await User.findOne({
        resetPasswordToken,
        resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
        return next(new ErrorHandler('Invalid reset token', 400));
    }

    // Set new password
    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();

    // Send response
    res.status(200).json({
        success: true,
        message: 'Password updated successfully',
    });
});

// Update user profile
exports.updateUserProfile = asyncErrorHandler(async (req, res, next) => {
    try {
        // Find the user by ID
        const user = await User.findById(req.user.id);
        if (!user) {
            return next(new ErrorHandler(404, 'User not found.'));
        }

        // Ensure user is authorized to update their own profile
        if (req.user.id !== user.id) {
            return next(new ErrorHandler(403, 'Unauthorized to update this profile.'));
        }

        // Extract fields to update from the request body
        const { name, email } = req.body;
        const fieldsToUpdate = {};
        if (name) fieldsToUpdate.name = name;
        if (email) fieldsToUpdate.email = email;

        // Handle avatar upload if available
        if (req.file) {
            const avatarUpload = await cloudinary.v2.uploader.upload(req.file.path, {
                folder: 'avatars',
                width: 150,
                crop: 'scale',
            });
            fieldsToUpdate.avatar = {
                public_id: avatarUpload.public_id,
                url: avatarUpload.secure_url,
            };
        }

        // Update user profile
        const updatedUser = await User.findByIdAndUpdate(req.user.id, fieldsToUpdate, {
            new: true,
            runValidators: true,
        });

        // Send JWT token in response upon successful update
        sendJWtToken(updatedUser, 200, res);
    } catch (error) {
        // Handle any errors
        console.error(error);
        next(new ErrorHandler(500, 'An error occurred while updating user profile.'));
    }
});
// Admin operations

// Get all users (Admin)
exports.getAllUsers = asyncErrorHandler(async (req, res, next) => {
    try {
        // Ensure the user is authorized as an admin
        if (req.user.role !== 'admin') {
            return next(new ErrorHandler(403, 'Unauthorized to access this resource.'));
        }

        // Fetch all users from the database
        const users = await User.find();

        // Send response with user data
        res.status(200).json({
            success: true,
            count: users.length,
            users,
        });
    } catch (error) {
        // Handle any errors
        console.error(error);
        next(new ErrorHandler(500, 'An error occurred while fetching users.'));
    }
});

// Get single user by ID (Admin)
exports.getUserById = asyncErrorHandler(async (req, res, next) => {
    try {
        // Ensure the user is authorized as an admin
        if (req.user.role !== 'admin') {
            return next(new ErrorHandler(403, 'Unauthorized to access this resource.'));
        }

        // Find user by ID
        const user = await User.findById(req.params.id);

        // Check if user exists
        if (!user) {
            return next(new ErrorHandler(`User not found with id ${req.params.id}`, 404));
        }

        // Send JWT token response
        sendJWtToken(user, 200, res);
    } catch (error) {
        // Handle any errors
        console.error(error);
        next(new ErrorHandler(500, 'An error occurred while fetching user by ID.'));
    }
});

// Update user details by ID (Admin)
exports.updateUserById = asyncErrorHandler(async (req, res, next) => {
    try {
        // Define fields to update
        const fieldsToUpdate = {
            name: req.body.name,
            email: req.body.email,
            role: req.body.role,
        };

        // Find and update user by ID
        const user = await User.findByIdAndUpdate(req.params.id, fieldsToUpdate, {
            new: true, // Return updated user
            runValidators: true, // Run validators for updated fields
        });

        // Check if user exists
        if (!user) {
            return next(new ErrorHandler(`User not found with id ${req.params.id}`, 404));
        }

        // Send response with updated user
        res.status(200).json({
            success: true,
            message: 'User updated successfully',
            user,
        });
    } catch (error) {
        // Handle errors
        console.error(error);
        next(new ErrorHandler(500, 'An error occurred while updating user details.'));
    }
});
// Delete user by ID (Admin)
exports.deleteUserById = asyncErrorHandler(async (req, res, next) => {
    const user = await User.findById(req.params.id);

    // Check if user exists
    if (!user) {
        return next(new ErrorHandler(`User not found with id ${req.params.id}`, 404));
    }

    // Remove user
    await user.remove();

    // Send response
    res.status(200).json({
        success: true,
        message: 'User deleted successfully',
    });
});
