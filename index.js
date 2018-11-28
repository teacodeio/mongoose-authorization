// const _ = require('lodash')
const {
  hasPermission,
  authIsDisabled,
  sanitizeDocumentList
} = require('./lib/helpers')

const {
  FIND
} = require('./lib/constants')

const PermissionDeniedError = require('./lib/PermissionDeniedError')

module.exports = (schema) => {
  /**
   * ACL find
   * @param query
   * @param docs
   * @param next
   * @returns {*}
   * @private
   */
  function _find (query, docs, next) {
    if (!hasPermission(schema, query.options, FIND)) {
      return next(new PermissionDeniedError(FIND))
    }
    const sanitizedResult = sanitizeDocumentList(schema, query.options, docs)

    return next(null, sanitizedResult)
  }

  /**
   * Post find hook
   * @param doc
   * @param next
   * @returns {*}
   * @private
   */
  function _postFind (doc, next) {
    if (authIsDisabled(this.options)) return next()

    return _find(this, doc, next)
  }

  schema.post('find', _postFind)

  schema.query.setAuthLevel = _setAuthLevel
}

/**
 * Set auth level in query chain
 * @param authLevel
 * @returns {setAuthLevel}
 */
function _setAuthLevel (authLevel) {
  this.options.authLevel = authLevel
  return this
}
