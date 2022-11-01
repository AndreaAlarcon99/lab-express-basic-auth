const isLoggedOut = (req, res, next) => {
    if(!req.session.currentUser) next()
    else res.redirect("/users/profile")
}
module.exports = isLoggedOut