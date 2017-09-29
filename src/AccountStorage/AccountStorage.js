const TEN_YEARS = 1000 * 60 * 60 * 24 * 365 * 10

/* eslint-disable class-methods-use-this */
class CookieStorage {
  static get name() {
    return 'cookieStorage'
  }

  setItem(item, data) {
    const expire = new Date()
    expire.setTime(expire.getTime() + TEN_YEARS)

    document.cookie = `${item}=${data}; expires=${expire.toUTCString()}`
  }

  getItem(item) {
    const key = `${item}=`
    const allCookies = document.cookie.split(';')

    let value = null

    allCookies.forEach((cookieItem) => {
      let currentItem = cookieItem

      while (cookieItem.charAt(0) === ' ') {
        currentItem = cookieItem.substring(1)
      }

      if (currentItem.indexOf(key) === 0) {
        value = currentItem.substring(key.length, currentItem.length)
      }
    })

    return value
  }

  removeItem(item) {
    document.cookie = `${item}=; expires=Thu, 01 Jan 1970 00:00:00 UTC`
  }
}

class CustomStorage {
  static get name() {
    return 'customStorage'
  }

  constructor() {
    this.storage = {}
  }

  setItem(item, data) {
    this.storage[item] = data
  }

  getItem(item) {
    return this.storage[item] || null
  }

  removeItem(item) {
    this.storage[item] = null
  }
}

function getStorage() {
  const localStorage = (typeof window !== 'undefined') ? window.localStorage : undefined

  // localStorage -> cookies -> custom storage
  if (isStorageAvailable(localStorage)) {
    localStorage.name = 'localStorage'

    return localStorage
  } else if (isStorageAvailable(CookieStorage)) {
    return CookieStorage
  }

  return CustomStorage
}

function isStorageAvailable(storage) {
  try {
    const testItem = '__storage_test__'
    const testData = { test: 'test' }

    storage.setItem(testItem, JSON.stringify(testData))

    const storedData = JSON.parse(storage.getItem(testItem))

    if (storedData.test !== testData.testData) {
      return false
    }

    storage.removeItem(testItem)

    return true
  } catch (e) {
    return false
  }
}

module.exports = getStorage()
