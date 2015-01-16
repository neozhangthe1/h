# Public: Creates a Date object from an ISO8601 formatted date String.
#
# string - ISO8601 formatted date String.
#
# Returns Date instance.
createDateFromISO8601 = (string) ->
  regexp = "([0-9]{4})(-([0-9]{2})(-([0-9]{2})" +
           "(T([0-9]{2}):([0-9]{2})(:([0-9]{2})(\.([0-9]+))?)?" +
           "(Z|(([-+])([0-9]{2}):([0-9]{2})))?)?)?)?"

  d = string.match(new RegExp(regexp))

  offset = 0
  date = new Date(d[1], 0, 1)

  date.setMonth(d[3] - 1) if d[3]
  date.setDate(d[5]) if d[5]
  date.setHours(d[7]) if d[7]
  date.setMinutes(d[8]) if d[8]
  date.setSeconds(d[10]) if d[10]
  date.setMilliseconds(Number("0." + d[12]) * 1000) if d[12]

  if d[14]
    offset = (Number(d[16]) * 60) + Number(d[17])
    offset *= ((d[15] == '-') ? 1 : -1)

  offset -= date.getTimezoneOffset()
  time = (Number(date) + (offset * 60 * 1000))

  date.setTime(Number(time))
  date

base64Decode = (data) ->
  if atob?
    # Gecko and Webkit provide native code for this
    atob data
  else
    # Adapted from MIT/BSD licensed code at http://phpjs.org/functions/base64_decode
    # version 1109.2015
    b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    i = 0
    ac = 0
    dec = ""
    tmp_arr = []

    if not data
      return data

    data += ''

    while i < data.length
      # unpack four hexets into three octets using index points in b64
      h1 = b64.indexOf data.charAt(i++)
      h2 = b64.indexOf data.charAt(i++)
      h3 = b64.indexOf data.charAt(i++)
      h4 = b64.indexOf data.charAt(i++)

      bits = h1 << 18 | h2 << 12 | h3 << 6 | h4

      o1 = bits >> 16 & 0xff
      o2 = bits >> 8 & 0xff
      o3 = bits & 0xff

      if h3 == 64
        tmp_arr[ac++] = String.fromCharCode o1
      else if h4 == 64
        tmp_arr[ac++] = String.fromCharCode o1, o2
      else
        tmp_arr[ac++] = String.fromCharCode o1, o2, o3

    tmp_arr.join('')

base64UrlDecode = (data) ->
  m = data.length % 4
  if m != 0
    for i in [0...4 - m]
      data += '='
  data = data.replace /-/g, '+'
  data = data.replace /_/g, '/'
  base64Decode data

parseToken = (token) ->
  [head, payload, sig] = token.split '.'
  JSON.parse base64UrlDecode payload

###*
# @ngdoc service
# @name  Token
#
# @description
# The 'Token' service provides Authentication headers and
# fetches and parses token from the server.
###
class Token
  requestInProgress = false
  refreshTimeout = null

  waitingForToken = []
  tokenUrl = null

  token = null
  _unsafeToken = null

  element = null

  this.$inject = ['$document', 'documentHelpers']
  constructor:   ( $document,   documentHelpers) ->
    element = $document.find 'body'
    @setTokenUrl = (assertion) ->
      tokenUrl = documentHelpers.absoluteURI(
        "/api/token?assertion=#{assertion}")

  getToken: (callback) ->
    return unless callback?

    if haveValidToken()
      callback(_unsafeToken)
    else
      waitingForToken.push(callback)
      requestToken() unless requestInProgress

  forgetToken: ->
    token = null
    _unsafeToken = null

  # Private: Makes a request to the local server for an authentication token.
  #
  # Examples
  #   auth.requestToken()
  #
  # Returns jqXHR object.
  requestToken = () ->
    requestInProgress = true

    $.ajax
      url: tokenUrl
      dataType: 'text'
      xhrFields:
        withCredentials: true # Send any auth cookies to the backend

    # on success, set the auth token
    .done (data, status, xhr) =>
      setToken(data)

    # on failure, relay any message given by the server to the user with a notification
    .fail (xhr, status, err) =>
      msg = "Couldn't get auth token:"
      #TODO: Flash service
      console.error "#{msg} #{err}", xhr
#      Annotator.showNotification("#{msg} #{xhr.responseText}", Annotator.Notification.ERROR)

    # always reset the requestInProgress indicator
    .always =>
      requestInProgress = false

  # Private: Sets the @token and checks it's validity. If the token is invalid
  # requests a new one from the server.
  #
  # token - A token string.
  #
  # Examples
  #   setToken('eyJh...9jQ3I')
  #
  # Returns nothing.
  setToken = (token) ->
    token = token
    # Parse the token without verifying its authenticity:
    _unsafeToken = parseToken(token)

    if haveValidToken()
      # Set timeout to fetch new token 2 seconds before current token expiry
      refreshTimeout = setTimeout (() -> requestToken()), (timeToExpiry() - 2) * 1000

      # Set headers field on this.element
      updateHeaders()

      # Run callbacks waiting for token
      while waitingForToken.length > 0
        waitingForToken.pop()(_unsafeToken)
    else
        setTimeout ( -> requestToken()), 10 * 1000

  # Private: Checks the validity of the current token. Note that this *does
  # not* check the authenticity of the token.
  #
  # Examples
  #   haveValidToken() # => Returns true if valid.
  #
  # Returns true if the token is valid.
  haveValidToken = ->
    allFields = _unsafeToken &&
                _unsafeToken.issuedAt &&
                _unsafeToken.ttl &&
                _unsafeToken.consumerKey

    allFields and timeToExpiry() > 0

  # Private: Calculates the time in seconds until the current token expires.
  #
  # Returns Number of seconds until token expires.
  timeToExpiry = ->
    now = new Date().getTime() / 1000
    issue = createDateFromISO8601(_unsafeToken.issuedAt).getTime() / 1000

    expiry = issue + _unsafeToken.ttl
    expiryTime = expiry - now
    Math.max expiryTime, 0

  # Private: Updates the headers to be sent with the Store requests. This is
  # achieved by updating the 'annotator:headers' key in the @element.data()
  # store.
  #
  # Returns nothing.
  updateHeaders = ->
    current = element.data('annotator:headers')
    element.data('annotator:headers', $.extend(current, {
      'x-annotator-auth-token': token,
    }))

angular.module('h')
.service('token', Token)
