import gulp from 'gulp'
import { deleteAsync } from 'del'
import uglify from 'gulp-uglify'
import cleanCSS from 'gulp-clean-css'
import rename from 'gulp-rename'
import wpPot from 'gulp-wp-pot'
import zip from 'gulp-zip'
import fs from 'fs' // Import file system module
import path from 'path' // Import path module

// File paths
const paths = {
    js: ['assets/js/**/*.js', '!assets/js/**/*.min.js'], // Exclude already minified JS
    css: ['assets/css/**/*.css', '!assets/css/**/*.min.css'], // Exclude already minified CSS
    pot: '**/*.php', // PHP files for the .pot generation
    plugin: './', // Plugin root directory
    languages: 'languages/', // Language directory
}

// Minify JavaScript
gulp.task('minify-js', () => {
    return gulp
        .src(paths.js)
        .pipe(uglify())
        .pipe(rename({ suffix: '.min' }))
        .pipe(gulp.dest('assets/js'))
})

// Minify CSS
gulp.task('minify-css', () => {
    return gulp
        .src(paths.css)
        .pipe(cleanCSS({ compatibility: 'ie8' }))
        .pipe(rename({ suffix: '.min' }))
        .pipe(gulp.dest('assets/css'))
})

// Generate .pot file for translations (with directory creation)
gulp.task('generate-pot', (done) => {
    if (!fs.existsSync(paths.languages)) {
        fs.mkdirSync(paths.languages, { recursive: true }) // Ensure directory exists
    }

    return gulp
        .src(paths.pot)
        .pipe(
            wpPot({
                domain: 'cloudflare-ip-blocker',
                package: 'Polar Mass Advanced IP Blocker',
                team: 'Polar Mass',
            })
        )
        .pipe(gulp.dest(path.join(paths.languages, 'cloudflare-ip-blocker.pot')))
})

// Rename files before zipping
gulp.task('rename-files', (done) => {
    if (fs.existsSync('README.md')) {
        fs.renameSync('README.md', 'readme.txt')
    }
    if (fs.existsSync('LICENSE')) {
        fs.renameSync('LICENSE', 'license.txt')
    }
    done()
})

// Copy plugin files to release/cloudflare-ip-blocker before zipping
gulp.task('copy', () => {
    return gulp
        .src(['**/*', '!node_modules/**', '!gulpfile.js', '!package.json', '!package-lock.json', '!release/**', '!README.md', '!LICENSE'])
        .pipe(gulp.dest('release/cloudflare-ip-blocker'))
})

// Zip the cloudflare-ip-blocker folder inside release/
gulp.task(
    'zip',
    gulp.series('copy', () => {
        return gulp.src('release/cloudflare-ip-blocker/**/*', { base:'release' }).pipe(zip('cloudflare-ip-blocker.zip')).pipe(gulp.dest('release'))
    })
)

// Clean up the release/cloudflare-ip-blocker folder after zipping
gulp.task('clean', () => {
    return deleteAsync('release/cloudflare-ip-blocker')
})

// Restore original filenames after zipping
gulp.task('restore-files', (done) => {
    if (fs.existsSync('readme.txt')) {
        fs.renameSync('readme.txt', 'README.md')
    }
    if (fs.existsSync('license.txt')) {
        fs.renameSync('license.txt', 'LICENSE')
    }
    done()
})

// Define a build task to run everything
gulp.task('build', gulp.series('clean', 'minify-js', 'minify-css', 'generate-pot', 'rename-files', 'copy', 'zip', 'restore-files', 'clean'))

// Watch task for development
gulp.task('watch', () => {
    gulp.watch(paths.js, gulp.series('minify-js'))
    gulp.watch(paths.css, gulp.series('minify-css'))
})
