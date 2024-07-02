import { User } from "../models/user.model"
import { ApiError } from "./ApiError"

const generateAccessAndRefreshToken = async (userId) => {

    try {

        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validatebeforesave: false })
        return { accessToken, refreshToken }

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating access and refresh tokens")
    }

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")
}

export { generateAccessAndRefreshToken }