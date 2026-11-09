'use strict';

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/** A reference JSON file is missing or unreadable. */
class DataError extends HttpError {
  constructor(message) {
    super(503, message);
  }
}

module.exports = { HttpError, DataError };
