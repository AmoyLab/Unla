#!/usr/bin/env node

import fs from 'fs';
import https from 'https';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// 所有使用的图标列表
const icons = [
  // Lucide icons
  'lucide:server', 'lucide:user', 'lucide:lock', 'lucide:languages', 'lucide:plus',
  'lucide:x', 'lucide:check', 'lucide:chevron-right', 'lucide:chevron-left',
  'lucide:message-square', 'lucide:history', 'lucide:users', 'lucide:building',
  'lucide:sun', 'lucide:moon', 'lucide:key', 'lucide:log-out', 'lucide:search',
  'lucide:edit', 'lucide:more-vertical', 'lucide:trash-2', 'lucide:download',
  'lucide:loader-2', 'lucide:arrow-right', 'lucide:copy', 'lucide:external-link',
  'lucide:send', 'lucide:route', 'lucide:terminal', 'lucide:radio', 'lucide:globe',
  'lucide:wrench', 'lucide:trash', 'lucide:upload', 'lucide:play',
  'lucide:pencil',
  
  // Material Design icons
  'mdi:wechat', 'mdi:github', 'mdi:book-open-page-variant',
  
  // Material Symbols icons
  'material-symbols:add', 'material-symbols:upload', 'material-symbols:sync',
  'material-symbols:grid-view', 'material-symbols:table-rows',
  
  // Ionic icons
  'ic:baseline-discord', 'ic:round-unfold-more', 'ic:round-unfold-less',
  
  // Remix Icon icons
  'ri:menu-unfold-line', 'ri:menu-unfold-2-line',
  
  // Heroicons icons
  'heroicons:arrow-uturn-left', 'heroicons:chevron-left', 'heroicons:chevron-right',
  
  // Fluent UI MDL2 icons
  'fluent-mdl2:chevron-fold-10'
];

const publicDir = path.join(__dirname, '..', 'public', 'icons');

// 确保目录存在
if (!fs.existsSync(publicDir)) {
  fs.mkdirSync(publicDir, { recursive: true });
}

async function downloadIcon(iconName) {
  return new Promise((resolve, reject) => {
    const url = `https://api.iconify.design/${iconName}.svg`;
    const filePath = path.join(publicDir, `${iconName.replace(':', '-')}.svg`);
    
    console.log(`下载图标: ${iconName}`);
    
    https.get(url, (response) => {
      if (response.statusCode === 200) {
        const file = fs.createWriteStream(filePath);
        response.pipe(file);
        file.on('finish', () => {
          file.close();
          console.log(`✓ 已下载: ${iconName}`);
          resolve();
        });
      } else {
        console.error(`✗ 下载失败: ${iconName} (${response.statusCode})`);
        reject(new Error(`HTTP ${response.statusCode}`));
      }
    }).on('error', (err) => {
      console.error(`✗ 网络错误: ${iconName}`, err.message);
      reject(err);
    });
  });
}

async function downloadAllIcons() {
  console.log(`开始下载 ${icons.length} 个图标...`);
  
  for (const icon of icons) {
    try {
      await downloadIcon(icon);
      // 添加小延迟避免请求过快
      await new Promise(resolve => globalThis.setTimeout(resolve, 100));
    } catch (error) {
      console.error(`下载 ${icon} 失败:`, error.message);
    }
  }
  
  console.log('图标下载完成！');
}

// 生成图标映射文件
function generateIconMap() {
  const iconMap = {};
  icons.forEach(icon => {
    const fileName = `${icon.replace(':', '-')}.svg`;
    iconMap[icon] = `/icons/${fileName}`;
  });
  
  const mapFilePath = path.join(publicDir, 'icon-map.json');
  fs.writeFileSync(mapFilePath, JSON.stringify(iconMap, null, 2));
  console.log('图标映射文件已生成: public/icons/icon-map.json');
}

// 执行下载
downloadAllIcons().then(() => {
  generateIconMap();
}).catch(console.error);