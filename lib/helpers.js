const _ = require('lodash')

const {
  FIND,
  READ,
  WRITE,
  REMOVE
} = require('./constants')

/**
 * Resolves auth level from options and from getAuthLevel method
 * @param schema
 * @param options
 * @param doc
 * @returns {*}
 */
function resolveAuthLevel (schema, options, doc) {
  // Look into options the options and try to find authLevels. Always prefer to take
  // authLevels from the direct authLevel option as opposed to the computed
  // ones from getAuthLevel in the schema object.
  let authLevels = []
  if (options) {
    if (options.authLevel) {
      authLevels = _.castArray(options.authLevel)
    } else if (typeof schema.getAuthLevel === 'function') {
      authLevels = _.castArray(schema.getAuthLevel(options.authPayload, doc))
    }
  }
  // Add `defaults` to the list of levels since you should always be able to do what's specified
  // in defaults.
  authLevels.push('defaults')

  const perms = schema.permissions || {}
  return _.chain(authLevels)
    .filter(level => !!perms[level]) // make sure the level in the permissions dict
    .uniq() // get rid of fields mentioned in multiple levels
    .value()
}

function getAuthorizedFields (schema, options, action, doc) {
  const authLevels = resolveAuthLevel(schema, options, doc)

  return _.chain(authLevels)
    .flatMap(level => schema.permissions[level][action])
    .filter(path => schema.pathType(path) !== 'adhocOrUndefined') // ensure fields are in schema
    .uniq() // dropping duplicates
    .value()
}

/**
 * Check
 * @param schema
 * @param options
 * @param action
 * @param doc
 * @returns {boolean}
 */
function hasPermission (schema, options, action, doc) {
  const authLevels = resolveAuthLevel(schema, options, doc)
  const perms = schema.permissions || {}

  // look for any permissions setting for this action that is set to true (for these authLevels)
  return _.some(authLevels, level => perms[level][action])
}

/**
 * Check if authentication is disabled
 * @param options
 * @returns {*|boolean}
 */
function authIsDisabled (options) {
  return options && options.authLevel === false
}

function getEmbedPermissions (schema, options, doc) {
  return {
    [READ]: getAuthorizedFields(schema, options, READ, doc),
    [WRITE]: getAuthorizedFields(schema, options, WRITE, doc),
    [REMOVE]: hasPermission(schema, options, REMOVE, doc),
    [FIND]: hasPermission(schema, options, FIND, doc)
  }
}

/**
 * Clean up one document
 * @param schema
 * @param options
 * @param doc
 * @returns {*}
 */
function sanitizeDocument (schema, options, doc) {
  const authorizedFields = getAuthorizedFields(schema, options, READ, doc)

  if (!doc || authorizedFields.length === 0) return false

  let innerDoc = {}
  if (doc._doc) {
    innerDoc = { ...doc._doc }
  } else {
    innerDoc = { ...doc }
  }

  // sanitize inner document
  innerDoc = _.pick(innerDoc, authorizedFields)

  if (_.isEmpty(innerDoc)) {
    // There are no fields that can be seen, just return now
    return false
  }

  let sanitizeDoc = doc
  if (doc._doc) {
    sanitizeDoc._doc = innerDoc
  } else {
    sanitizeDoc = innerDoc
  }

  // Check to see if we're going to be inserting the permissions info
  if (options.permissions) {
    sanitizeDoc.permissions = getEmbedPermissions(schema, options, doc)
  }

  return doc
}

/**
 * Clean up a list of documents
 * @param schema
 * @param options
 * @param docs
 * @returns {*}
 */
function sanitizeDocumentList (schema, options, docs) {
  const multi = _.isArrayLike(docs)
  const docList = _.castArray(docs)

  const filteredResult = _.chain(docList)
    .map(doc => sanitizeDocument(schema, options, doc))
    .filter(doc => doc) // filters out false documents
    .value()

  return multi ? filteredResult : filteredResult[0]
}

function getUpdatePaths (updates) {
  // query._update is sometimes in the form of `{ $set: { foo: 1 } }`, where the top level
  // is atomic operations. See: http://mongoosejs.com/docs/api.html#query_Query-update
  // For findOneAndUpdate, the top level may be the fields that we want to examine.
  return _.flatMap(updates, (val, key) => {
    if (_.startsWith(key, '$')) {
      return Object.keys(val)
    }

    return key
  })
}

module.exports = {
  resolveAuthLevel,
  getAuthorizedFields,
  hasPermission,
  authIsDisabled,
  sanitizeDocumentList,
  getUpdatePaths
}
