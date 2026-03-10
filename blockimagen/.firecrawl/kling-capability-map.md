The Kling 3.0 series models API is now fully available

Learn More

- Getting Started

  - [Product Introduction](https://app.klingai.com/dev/document-api/quickStart/productIntroduction/overview)
  - [Video Effects Center\\
    NEW](https://app.klingai.com/dev/document-api/quickStart/productIntroduction/effectsCenter)
  - [Quick Start](https://app.klingai.com/dev/document-api/quickStart/userManual)
- API Reference

  - [Update Announcement](https://app.klingai.com/dev/document-api/apiReference/updateNotice)
  - [General Information](https://app.klingai.com/dev/document-api/apiReference/commonInfo)
  - [Rate Limits](https://app.klingai.com/dev/document-api/apiReference/rateLimits)
  - API Calls

    - [Capability Map](https://app.klingai.com/dev/document-api/apiReference/model/skillsMap)
    - [Omni Image](https://app.klingai.com/dev/document-api/apiReference/model/OmniImage)
    - [Image Generation](https://app.klingai.com/dev/document-api/apiReference/model/imageGeneration)
    - [Multi-Image to Image](https://app.klingai.com/dev/document-api/apiReference/model/multiImageToImage)
    - [Image Expansion](https://app.klingai.com/dev/document-api/apiReference/model/imageExpansion)
    - [AI Multi-Shot](https://app.klingai.com/dev/document-api/apiReference/model/aiMultiShot)
    - [Omni Video](https://app.klingai.com/dev/document-api/apiReference/model/OmniVideo)
    - [Text to Video](https://app.klingai.com/dev/document-api/apiReference/model/textToVideo)
    - [Image to Video](https://app.klingai.com/dev/document-api/apiReference/model/imageToVideo)
    - [Multi-Image to Video](https://app.klingai.com/dev/document-api/apiReference/model/multiImageToVideo)
    - [Motion Control](https://app.klingai.com/dev/document-api/apiReference/model/motionControl)
    - [Multi-Elements](https://app.klingai.com/dev/document-api/apiReference/model/multiElements)
    - [Video Extension](https://app.klingai.com/dev/document-api/apiReference/model/videoExtension)
    - [Avatar](https://app.klingai.com/dev/document-api/apiReference/model/avatar)
    - [Lip-Sync](https://app.klingai.com/dev/document-api/apiReference/model/lipSync)
    - [Video Effects](https://app.klingai.com/dev/document-api/apiReference/model/videoEffects)
    - [Text to Audio](https://app.klingai.com/dev/document-api/apiReference/model/textToAudio)
    - [Video to Audio](https://app.klingai.com/dev/document-api/apiReference/model/videoToAudio)
    - [TTS](https://app.klingai.com/dev/document-api/apiReference/model/TTS)
    - [Image Recognize](https://app.klingai.com/dev/document-api/apiReference/model/imageRecognize)
    - [Element](https://app.klingai.com/dev/document-api/apiReference/model/element)
    - [Custom Voices](https://app.klingai.com/dev/document-api/apiReference/model/customVoices)
    - [Virtual Try-On](https://app.klingai.com/dev/document-api/apiReference/model/virtualTryOn)
  - [Callback Protocol](https://app.klingai.com/dev/document-api/apiReference/callbackProtocol)
  - [Account Information Inquiry](https://app.klingai.com/dev/document-api/apiReference/accountInfoInquiry)
- 【API】Billing

  - [Billing](https://app.klingai.com/dev/document-api/productBilling/billingMethod)
  - [Prepaid Resource Packs](https://app.klingai.com/dev/document-api/productBilling/prePaidResourcePackage)
- Related Protocols

  - [Privacy Policy of API Service](https://app.klingai.com/dev/document-api/protocols/privacyPolicy)
  - [Terms of API Service](https://app.klingai.com/dev/document-api/protocols/paidServiceProtocol)
  - [API Service Level Agreement](https://app.klingai.com/dev/document-api/protocols/paidLevelProtocol)

# Capability Map

* * *

## Video Generation

| kling-video-o1 | std（3s～10s） | pro（3s～10s） |
| text to video | single-shot-video generation | ✅（only 5s、10s） | ✅（only 5s、10s） |
| voice control | ❌ | ❌ |
| others | - | - |
| image to video | single-shot-video generation<br>（only start frame） | ✅（only 5s、10s） | ✅（only 5s、10s） |
| start & end frame | ✅ | ✅ |
| element control<br>（only multi-image elements） | ✅ | ✅ |
| cideo reference<br>(including multi-image elements) | ✅ | ✅ |
| voice control | ❌ | ❌ |
| others | - | - |

| kling-v3-omni | std（3s～15s） | pro（3s～15s） |
| text to video | single-shot-video generation | ✅ | ✅ |
| multi-shot-video generation | ✅ | ✅ |
| voice control | ❌ | ❌ |
| others | - | - |
| image to video | single-shot-video generation | ✅ | ✅ |
| multi-shot-video generation | ✅ | ✅ |
| start & end frame | ✅ | ✅ |
| element control<br>（video character elements & multi-image elements） | ✅ | ✅ |
| reference video | ✅（only 3s～10s） | ✅（only 3s～10s） |
| voice control | ❌ | ❌ |
| others | - | - |

| kling-v1 | std 5s | std 10s | pro 5s | pro10s |
| text<br>to video | video generation | ✅ | ✅ | ✅ | ✅ |
| camera control | ✅ | - | - | - |
| image<br>to video | video generation | ✅ | ✅ | ✅ | ✅ |
| start/end frame | ✅ | - | ✅ | - |
| motion brush | ✅ | - | ✅ | - |
| others | - | - | - | - |
| video extension<br>（Not supported negative\_prompt and cfg\_scale) | ✅ | ✅ | ✅ | ✅ |
| video effects<br>Dual-character: Hug, Kiss, heart\_gesture | ✅ | ✅ | ✅ | ✅ |
| others | - | - | - | - |

| kling-v1-5 | std 5s | std 10s | pro 5s | pro10s |
| text<br>to video | video generation | - | - | - | - |
| others | - | - | - | - |
| image<br>to video | video generation | ✅ | ✅ | ✅ | ✅ |
| start/end frame | - | - | ✅ | ✅ |
| end frame | - | - | ✅ | ✅ |
| motion brush | - | - | ✅ | - |
| camera control<br>（simple only） | - | - | ✅ | - |
| others | - | - | - | - |
| video extension | ✅ | ✅ | ✅ | ✅ |
| video effects<br>Dual-character: Hug, Kiss, heart\_gesture | ✅ | ✅ | ✅ | ✅ |
| others | - | - | - | - |

| kling-v1-6 | std 5s | std 10s | pro 5s | pro10s |
| text<br>to video | video generation | ✅ | ✅ | ✅ | ✅ |
| others | - | - | - | - |
| image<br>to video | video generation | ✅ | ✅ | ✅ | ✅ |
| start/end frame | - | - | ✅ | ✅ |
| end frame | - | - | ✅ | ✅ |
| others | - | - | - | - |
| multi-image2video | ✅ | ✅ | ✅ | ✅ |
| multi-elements | ✅ | ✅ | ✅ | ✅ |
| video extension | ✅ | ✅ | ✅ | ✅ |
| video effects<br>Dual-character: Hug, Kiss, heart\_gesture | ✅ | ✅ | ✅ | ✅ |

| kling-v2-master | 5s | 10s |
| text<br>to video | video generation | ✅ | ✅ |
| others | - | - |
| image<br>to video | video generation | ✅ | ✅ |
| others | - | - |
| others | - | - |

| kling-v2-1 | std 5s | std 10s | pro 5s | pro10s |
| text<br>to video | all | - | - | - | - |
| image<br>to video | video generation | ✅ | ✅ | ✅ | ✅ |
| start/end frame | - | - | ✅ | ✅ |
| others | - | - | - | - |
| others | - | - | - | - |

| kling-v2-1-master | 5s | 10s |
| text<br>to video | video generation | ✅ | ✅ |
| others | - | - |
| image<br>to video | video generation | ✅ | ✅ |
| others | - | - |
| others | - | - |

| kling-v2-5-turbo | std 5s | std 10s | pro 5s | pro10s |
| text<br>to video | video generation | ✅ | ✅ | ✅ | ✅ |
| others | - | - | - | - |
| image<br>to video | video generation | ✅ | ✅ | ✅ | ✅ |
| start/end frame | - | - | ✅ | ✅ |
| others | - | - | - | - |
| others | - | - | - | - |

| kling-v2-6 | std 5s | std 10s | std x other duration | pro 5s | pro10s | pro x other duration |
| text to video | video generation | ✅ (only no audio) | ✅ (only no audio) | - | ✅ | ✅ | - |
| others | - | - | - | - | - | - |
| image to video | video generation | ✅ (only no audio) | ✅ (only no audio) | - | ✅ | ✅ | - |
| start/end frame | - | - | - | ✅ (only no audio) | ✅ (only no audio) | - |
| voice control | - | - | - | ✅ | ✅ | - |
| motion control | - | - | ✅ | - | - | ✅ |
| others | - | - | - | - | - | - |

| kling-v3 | std（3～15s） | pro（3～15s） |
| text to video | single-shot-video generation | ✅ | ✅ |
| multi-shot-video generation | ✅ | ✅ |
| voice control | ❌ | ❌ |
| others | - | - |
| image to video | single-shot-video generation （only start frame） | ✅ | ✅ |
| multi-shot-video generation | ✅ | ✅ |
| start & end frame | ✅ | ✅ |
| element control<br>（video character elements & multi-image elements） | ✅ | ✅ |
| motion control | ✅ | ✅ |
| voice control | ❌ | ❌ |
| others | - | - |

| no related of model | support or not | description |
| avatar | ✅ | Generate digital human broadcast-style videos with just one photo |
| lip sync | ✅ | Can be combined with text or audio to drive the mouth shape of characters in the video |
| video to audio | ✅ | Supports adding audio to all videos generated by Kling models and user-uploaded videos |
| text to audio | - | Supports generating  audio by text prompts |
| others | - | - |

| Model | kling-v1 | kling-v1-5 | kling-v1-6<br>Image to Video | kling-v1-6<br>Text to Video | kling-v2 Master |
| Mode | STD | PRO | STD | PRO | STD | PRO | STD | PRO | - |
| Resolution | 720p | 720p | 720p | 1080p | 720p | 1080p | 720p | 1080p | 720p |
| Frame Rate | 30fps | 30fps | 30fps | 30fps | 30fps | 30fps | 24fps | 24fps | 24fps |

| Model | kling-v2-1<br>Image to Video | kling-v2-1 Master | kling-v2-5<br>Image to Video | kling-v2-5<br>Text to Video |
| Mode | STD | PRO | - | PRO | PRO |
| Resolution | 720p | 1080p | 1080p | 1080p | 1080p |
| Frame Rate | 24fps | 24fps | 24fps | 24fps | 24fps |

## Image Generation

| kling-image-o1 | custom aspect ratio（1K/2K） | intelligent aspect ratio |
| text to image | single-image generation | ✅ | ✅ |
| others | - | - |
| image to image | single-image generation | ✅ | ✅ |
| element control<br>（only multi-image elements） | ✅ | ✅ |
| others | - | - |

| kling-v3-omni | custom aspect ratio（1K/2K/4K） | intelligent aspect ratio |
| text to image | single-image generation | ✅ | ✅ |
| others | - | - |
| image to image | single-image generation | ✅ | ✅ |
| series-image generation | ✅ | ✅ |
| element control<br>（only multi-image elements） | ✅ | ✅ |
| others | - | - |

| kling-v1 | 1:1 | 16:9 | 4:3 | 3:2 | 2:3 | 3:4 | 9:16 | 21:9 |
| text to image | - | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | - |
| image to image | entire image | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | - |
| others | - | - | - | - | - | - | - | - |

| kling-v1-5 | 1:1 | 16:9 | 4:3 | 3:2 | 2:3 | 3:4 | 9:16 | 21:9 |
| text to image | - | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| image to image | subject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| face | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| others | - | - | - | - | - | - | - | - |

| kling-v2 | 1:1 | 16:9 | 4:3 | 3:2 | 2:3 | 3:4 | 9:16 | 21:9 |
| text to image | - | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| image to image | multi-image to image | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| restyle | ✅  (The resolution of the generated image is the same as that of the input image, and it does not support setting the resolution separately) |
| others | - | - | - | - | - | - | - | - |

| kling-v2-new | 1:1 | 16:9 | 4:3 | 3:2 | 2:3 | 3:4 | 9:16 | 21:9 |
| text to image | - | - | - | - | - | - | - | - | - |
| image to image | restyle | ✅  (The resolution of the generated image is the same as that of the input image, and it does not support setting the resolution separately) |
| others | - | - | - | - | - | - | - | - |

| kling-v2-1 | 1:1 | 16:9 | 4:3 | 3:2 | 2:3 | 3:4 | 9:16 | 21:9 |
| text to image | - | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| image to image | entire image | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | - |
| subject | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| face | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| multi-image to image | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| restyle | ✅  (The resolution of the generated image is the same as that of the input image, and it does not support setting the resolution separately) |

| kling-v3 | custom aspect ratio（1K/2K） | intelligent aspect ratio |
| text to image | single-image generation | ✅ | ✅ |
| others | - | - |
| image to image | single-image generation | ✅ | ✅ |
| element control<br>（only multi-image elements） | ✅ | ✅ |
| others | - | - |

| no related of model | support or not | description |
| image expansion | ✅ | Supports expand content based on existing images |
| others | - |  |

| Model | kling-v1 | kling-v1-5 | kling-2 |
| Feature | Text to Image | Image to Image | Text to Image | Image to Image | Text to Image | Image to Image |
| Resolution | 1K | 1K | 1K | 1K | 1K/2K | 1K |

Previous chapter：Rate Limits

Next chapter：Omni Image

Video Generation

Image Generation

The Kling 3.0 Series Models API is Now Fully Available
– All in One, One for All！

Models Available in This Release

Kling 3.0 Motion Control, Kling Video 3.0, Kling Video 3.0 Omni, Kling Image 3.0, Kling Image 3.0 Omni

Refer to [<Kling AI Series 3.0 Model API Specification>](https://docs.qingque.cn/d/home/eZQDkLsWj1-DlmBV0EQIOm9vu?identityId=2CFp2MveJ7c#section=h.f13f61edvoid)

- Key Highlights of the Models

3.0 All-in-One: A unified model for multi-modal input and output.

  - Most powerful consistency across the universe: Subject consistency (supports cameo, subject with voice control, i2v + subject) and text consistency.
  - Narrative control at your fingertips: More freedom, precision, and control—up to 15 seconds long, video scene cuts, ultra-high-definition storyboards/images, custom seconds.
  - Upgraded native audio-visual output: Supports multiple speakers and languages (with accents).
- Kling 3.0 Motion Control


  - Consistent Facial Identity from any angle
  - Complex Emotions faithfully reproduced
  - High fidelity Restoration, Even with Face Occlusions
  - Consistent Facial Clarity Across Dynamic Framing

[User Guide ->](https://app.klingai.com/global/quickstart/motion-control-user-guide)

- Kling Video 3.0

Compared to 2.6, expected improvements:


  - Supports subject upload in I2V scenarios for enhanced consistency
  - Significant improvement in multi-character referencing, especially for three-person scenarios
  - Supports Japanese, Korean, and Spanish in addition to Chinese and English
  - Capable of generating certain dialects and accents
  - Better distinction and control over different types of audio (speech, sound effects, BGM)
  - Improved text retention in I2V scenarios
  - Supports scene transitions, with up to 6 shots and customizable storyboarding

[User Guide ->](https://app.klingai.com/global/quickstart/klingai-video-3-model-user-guide)

- Kling Video 3.0 Omni

Compared to O1, expected improvements:


  - Native audio-visual synchronization
  - Supports video subject creation
  - Further improved consistency in reference-based tasks, especially for characters and products
  - Combined capabilities of reference + storyboarding + audio-visual sync significantly enhance usability
  - Supports scene transitions, with up to 6 shots
  - Extended generation duration up to 15 seconds

[User Guide ->](https://app.klingai.com/global/quickstart/klingai-video-3-omni-model-user-guide)

- Kling Image 3.0


  - Highly consistent feature retention
  - Precise response to detail modifications
  - Accurate control over style and tone
  - Rich imaginative capabilities

[User Guide ->](https://app.klingai.com/global/quickstart/klingai-image-3-model-user-guide)

- Kling Image 3.0 Omni


  - Enhanced narrative sense
  - New storyboard image set generation, retaining reference image features with scene relevance
  - Direct output of 2K/4K ultra-high-definition images
  - Further improved detail consistency

[User Guide ->](https://app.klingai.com/global/quickstart/klingai-image-3-omni-user-guide)

Thank you for your support and understanding!

I Got It