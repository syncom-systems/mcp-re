import {defineConfig} from 'vite';
import motionCanvasPackage from '@motion-canvas/vite-plugin';
import ffmpegPackage from '@motion-canvas/ffmpeg';

const motionCanvas =
  typeof motionCanvasPackage === 'function'
    ? motionCanvasPackage
    : (motionCanvasPackage as any).default;

const ffmpeg =
  typeof ffmpegPackage === 'function'
    ? ffmpegPackage
    : (ffmpegPackage as any).default;

export default defineConfig({
  plugins: [
    motionCanvas({
      project: ['./src/project.ts', './src/preamble.ts'],
      output: './dist',
    }),
    ffmpeg(),
    // The Motion Canvas plugin targets `modules`, a Vite alias Vite 8 no longer accepts.
    // This replaces it with the browser set that alias named. Assigned rather than returned:
    // Vite merges a returned target with the plugin's by concatenation.
    {
      name: 'mcps-intro:build-target',
      enforce: 'post',
      config(config) {
        if (config.build?.target === 'modules') {
          config.build.target = ['es2020', 'edge88', 'firefox78', 'chrome87', 'safari14'];
        }
      },
    },
  ],
  build: {
    outDir: 'dist/build',
  },
});
