Quick Setup Guide

This guide helps set up the BardoQuant project for development or publishing.

Quick Start for Users

To use BardoQuant in your project, add the dependency io.github.bardoquant:bardoquant:2.0.0 to the build file. See INSTALL.md for details.

Developer Setup

1. Prerequisites: Ensure Java 17 or higher and recent Git.

2. Clone Repository: Clone from the GitHub URL and navigate to the directory.

3. Generate Gradle Wrapper if not present: Create wrapper version 8.5 for building without global Gradle, adding scripts and properties. Alternatively, download the distribution manually.

4. Make Gradle Wrapper Executable on Unix/Mac: Set permissions if needed.

5. Build the Project: Use the wrapper to build, expecting successful output.

6. Run Tests: Use the wrapper for tests, or with coverage report.

7. Run Examples: In examples directory, compile and run with the built JAR in classpath.

Publishing for Maintainers

Local Testing: Publish to local Maven, artifacts in user home .m2 repository.

Publishing to Maven Central: Configure credentials in properties file including Sonatype and signing details. Then publish and release the repository.

See README.md for overview and architecture.

Development Workflow

1. Create a Feature Branch: Checkout new branch.

2. Make Changes: Edit in src/main/kotlin/io/github/bardoquant/.

3. Run Tests: With the wrapper.

4. Check Code Style: Check with ktlint, or format to fix.

5. Build: With the wrapper.

6. Commit and Push: Add, commit, push to branch.

7. Create Pull Request: On GitHub.

Testing

Run All Tests: With wrapper.

Run Specific Test: With wrapper and tests filter.

Run with Coverage: With wrapper, view HTML report.

Run Examples as Tests: In examples, compile all files and run.

Troubleshooting

Gradle Wrapper Not Found: Generate wrapper 8.5, or download from site.

Permission Denied on Unix/Mac: Set executable.

OutOfMemoryError: Increase JVM args in properties to 4096m.

Dependency Resolution Failed: Clean and refresh dependencies.

IDE Not Recognizing Code: Invalidate caches and restart in IntelliJ, or reload in VS Code.

Additional Resources

README.md for main docs, INSTALL.md for user install, examples/README.md for usage.

Getting Help

Documentation in README.md, issues on GitHub, email support@bardoquant.io.

Checklist

Before PR: Code compiles, tests pass, new tests added, docs updated, style followed, no warnings.

Ready: Build and test.