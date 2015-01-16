###*
# @ngdoc service
# @name  Auth
#
# @description
# The 'Auth' service exposes the currently logged in user for other components,
# Requests/forgets token according to the login/logout events
# and provides a method for permitting a certain operation for a user with a
# given annotation
###
class Auth

  this.$inject = ['$location', '$rootScope',
                  'annotator', 'identity', 'token']
  constructor:   ( $location,   $rootScope,
                   annotator,   identity,   token) ->
    {plugins} = annotator
    _checkingToken = false
    @user = undefined

    # Fired when the identity-service successfully requests authentication.
    # Sets the auth.user property and a flag between that time period to
    # indicate that the token is being checked.
    onlogin = (assertion) =>
      _checkingToken = true

      # Configure the Auth plugin with the issued assertion as refresh token.
      token.setTokenUrl assertion

      # Set the user from the token.
      token.getToken (token) =>
        _checkingToken = false
        @user = token.userId
        $rootScope.$apply()

    # Fired when the identity-service forgets authentication.
    # Sets the user to null.
    onlogout = =>
      token.forgetToken()
      @user = null
      _checkingToken = false

    # Fired after the identity-service requested authentication (both after
    # a failed or succeeded request). It detects if the first login request
    # has failed and if yes, it sets the user value to null. (Otherwise the
    # onlogin method would set it to userId)
    onready = =>
      if @user is undefined and not _checkingToken
        @user = null

    identity.watch {onlogin, onlogout, onready}


angular.module('h')
.service('auth', Auth)
