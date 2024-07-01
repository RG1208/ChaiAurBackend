const asyncHandler = (requestHandler) => {
    return (req, res, next) => {
        Promise.resolve(requestHandler(req, res, next)).catch((err) => (next(err)))
    }
}


export { asyncHandler }







// const asyncHandler = (fn) => aysnc(req, res, next) => {
//     try {
//         await fn(req, res, next)
//     } catch (error) {
//         res.stauts(err.code || 500).json({

//             success: false,
//             message: err.message
//         })

//     }
// }
