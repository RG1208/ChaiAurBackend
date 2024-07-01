import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.model.js"

const registerUser = asyncHandler(async (req, res) => {
    // 1.get user details from user
    // 2.check for no empty fields
    // 3.check if user already exists (by email or username)
    // 4.check whether images and avatar is uploaded or not 
    // 5.upload avatar and image on cloudinary 
    // 6.create user object, create entry in db
    // 7.remove password and refresh token from response
    // 8.check wheter the user is now created or not
    // 9.return response or error

    // Getting input from user
    const { fullName, email, password, username } = req.body
    console.log("email:", email);

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

    // checking if user already 
    const existedUser = User.findOne({
        $or: [{ username }, { email }]
    })

    if (existedUser) {
        throw new ApiError(409, "User already exists with this username or email")
    }
})


export { registerUser }