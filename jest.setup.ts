/**
 * Jest setup file
 * This file is executed before each test file
 */

// Extend Jest matchers if needed
// import 'jest-extended';

// Set up global test configuration
beforeAll(() => {
  // Global setup before all tests
});

afterAll(() => {
  // Global cleanup after all tests
});

beforeEach(() => {
  // Setup before each test
});

afterEach(() => {
  // Cleanup after each test
});

// Mock console methods in tests to avoid noise
const originalConsole = global.console;

beforeEach(() => {
  global.console = {
    ...originalConsole,
    // Uncomment to suppress console.log in tests
    // log: jest.fn(),
    // warn: jest.fn(),
    // error: jest.fn(),
  };
});

afterEach(() => {
  global.console = originalConsole;
});

// Set timezone for consistent date testing
process.env.TZ = 'UTC';
