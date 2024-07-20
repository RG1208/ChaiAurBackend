import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.model.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js";
import { generateAccessAndRefreshToken } from "../utils/AccessRefreshToken.js";
import jwt from "jsonwebtoken";
// REGISTER USER
const registerUser = asyncHandler(async (req, res) => {
    // 1.get user details from user
    // 2.check for no empty fields
    // 3.check if user already exists (by email or username)
    // 4.check whether images and avatar is uploaded or not 
    // 5.upload avatar and image on cloudinary 
    // 6.create user object, create entry in db
    // 7.remove password and refresh token from response
    // 8.check wheter the user is now created or not
    // 9.return response

    // Getting input from user
    const { fullName, email, password, username } = req.body
    // console.log("email:", email);

    // checking from no empty field
    if (fullName === "") {
        throw new ApiError(400, "FullName is Mandatory")
    }
    else if (username === "") {
        throw new ApiError(400, "username is Mandatory")
    }
    else if (password === "") {
        throw new ApiError(400, "Password is Mandatory")
    }
    else if (email === "") {
        throw new ApiError(400, "email is Mandatory")
    }

    // checking if user already exists 
    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })

    if (existedUser) {
        throw new ApiError(409, "User already exists with this username or email")
    }

    // checking for images and avatar are uploaded by user or not 
    const avatarLocalPath = req.files?.avatar[0]?.path;

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path
    }


    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }

    // uploading image on cloudinary
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    if (!avatar) {
        throw new ApiError(400, "Avatar uploading is mandatory")
    }

    // create user object, create entry in db
    const user = await User.create({
        fullName,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        password,
        email,
        username: username.toLowerCase()
    })

    // remove password and refresh token from response
    const createdUser = await User.findById(user._id).select("-password -refreshToken")

    // check wheter the user is now created or not
    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    // return response
    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered Successfully ")
    )
})


// LOGIN USER

// 1.fetch data from req.body
// 2.username or email
// 3.find the user
// 4.check whether the password is correct or not 
// 5.generate access and refresh token
// 6.cookie

// fetching data from user
const loginUser = asyncHandler(async (req, res) => {
    const { email, username, password } = req.body

    // checking for no empty fields
    if (!email && username) {
        throw new ApiError(400, "Email or Username is Required")
    }

    // checking if user exits or not
    const user = await User.findOne({
        $or: [{ username }, { email }]
    })

    if (!user) {
        throw new ApiError(404, "User not found")
    }

    // check whether the password is correct or not
    const isPasswordValid = await user.isPasswordCorrect(password)

    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid user credentials")
    }

    // generate access and refresh token
    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(user._id)
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    // cookie
    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(200,
                {
                    user: loggedInUser, accessToken, refreshToken
                },
                "User LoggedIn Successfully"
            )
        )



})

// LOGOUT METHOD
const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined// this removes the field from document
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged Out"))
})

// Access and refresh token
const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if (!incomingRefreshToken) {
        throw new ApiError(401, "unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )

        const user = await User.findById(decodedToken?._id)

        if (!user) {
            throw new ApiError(401, "Invalid refresh token")
        }

        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used")

        }

        const options = {
            httpOnly: true,
            secure: true
        }

        const { accessToken, newRefreshToken } = await generateAccessAndRefereshTokens(user._id)

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    { accessToken, refreshToken: newRefreshToken },
                    "Access token refreshed"
                )
            )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }

})

// For changing password
const changeCurrentPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body

    const user = User.findById(req.user?._id)
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if (!isPasswordCorrect) {
        throw new ApiError(400, "password Incorrect")
    }

    user.password = newPassword
    await user.save({ validateBeforeSave: false })
    return res
        .status(200)
        .json(new ApiResponse(200, {}, "Password changed successfully"))
})

// get Current User
const getCurrentUser = asyncHandler(async (req, res) => {
    return res
        .status(200)
        .json(200, req.status, "current user fetched successfully")
})

// updating account details

const updateAccoutnDetails = asyncHandler(async (req, res) => {
    const { fullName, email } = req.body
    if (!fullName || !email) {
        throw new ApiError(400, "All fields are required")
    }
    const user = User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName,
                email: email
            }
        },
        { new: true }
    ).select("-password")
})



export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser
}