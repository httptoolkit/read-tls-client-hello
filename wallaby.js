module.exports = (wallaby) => {
  return {
    files: [
      'package.json',
      'src/**/*.ts',
      'test/**/*.ts',
      { pattern: 'test/fixtures/**/*', load: false, binary: true },
      '!test/**/*.spec.ts'
    ],
    tests: [
      'test/**/*.spec.ts'
    ],

    preprocessors: {
      // Package.json points `main` to the built output. We use this a lot in the tests, but we
      // want wallaby to run on raw source. This is a simple remap of paths to lets us do that.
      'test/**/*.ts': file => {
        return file.content.replace(
          /("|')\.\.("|')/g,
          '"../src/"'
        );
      }
    },

    workers: {
      initial: 1,
      regular: 1,
      restart: true
    },

    testFramework: 'mocha',
    env: {
      type: 'node'
    },
    debug: true
  };
};