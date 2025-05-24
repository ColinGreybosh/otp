# TypeScript Template

A comprehensive TypeScript template with maximum static analysis and code quality enforcement.

## Features

### Code Quality & Static Analysis

- **TypeScript**: Strict configuration with maximum type safety
- **ESLint**: Comprehensive linting with TypeScript-specific rules
- **Prettier**: Consistent code formatting
- **Husky**: Git hooks for automated quality checks
- **Lint-staged**: Run linters on staged files only
- **Import/Export**: Organized imports with automatic sorting
- **Security**: Security-focused linting rules
- **Unused Code Detection**: Automatic detection and removal of unused imports

### Development Experience

- **VS Code Integration**: Optimized settings and recommended extensions
- **EditorConfig**: Consistent editor configuration across teams
- **Path Mapping**: TypeScript path aliases for clean imports
- **Type Checking**: Comprehensive type checking with strict rules
- **Pre-commit Hooks**: Automated validation before commits

## Installation

1. **Clone the repository**:

   ```bash
   git clone <repository-url>
   cd typescript-template
   ```

2. **Install dependencies**:

   ```bash
   npm install
   ```

3. **Set up Git hooks**:

   ```bash
   npm run prepare
   ```

## Available Scripts

### Development

- `npm run dev` - Start TypeScript compiler in watch mode
- `npm run build:dev` - Build for development with source maps
- `npm run type-check` - Run TypeScript type checking
- `npm run type-check:watch` - Run type checking in watch mode

### Production

- `npm run build` - Build for production
- `npm run clean` - Remove build artifacts

### Code Quality

- `npm run lint` - Run ESLint
- `npm run lint:fix` - Run ESLint with auto-fix
- `npm run format` - Format code with Prettier
- `npm run format:check` - Check code formatting
- `npm run validate` - Run all validation checks (type-check + lint + format)

## Project Structure

```
├── src/
│   ├── lib/           # Core library implementations
│   ├── types/         # TypeScript type definitions
│   ├── utils/         # Utility functions
│   ├── __tests__/     # Test files
│   └── index.ts       # Main entry point
├── dist/              # Compiled output (generated)
├── .vscode/           # VS Code configuration
├── .husky/            # Git hooks
├── tsconfig.json      # Main TypeScript configuration
├── tsconfig.build.json # Production build configuration
├── tsconfig.dev.json  # Development configuration
├── eslint.config.mjs  # ESLint configuration
├── .prettierrc.json   # Prettier configuration
└── .editorconfig      # Editor configuration
```

## Configuration Files

### TypeScript Configuration

- **`tsconfig.json`**: Main configuration with strict type checking
- **`tsconfig.build.json`**: Production build configuration
- **`tsconfig.dev.json`**: Development configuration with relaxed settings

### ESLint Configuration

The ESLint configuration (`eslint.config.mjs`) includes:

- TypeScript-specific rules with strict type checking
- Import/export organization and validation
- Security-focused linting rules
- Unused code detection
- Code complexity rules
- Prettier integration

### Prettier Configuration

Consistent code formatting with TypeScript-optimized settings:

- Single quotes for strings
- Trailing commas (ES5)
- 2-space indentation
- 80-character line width
- LF line endings

## Path Aliases

The project uses TypeScript path mapping for clean imports:

Available aliases:

- `@/*` → `src/*`
- `@/types/*` → `src/types/*`
- `@/utils/*` → `src/utils/*`
- `@/lib/*` → `src/lib/*`
