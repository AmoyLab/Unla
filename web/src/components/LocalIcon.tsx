import React, { useState, useEffect } from 'react';

import iconMap from '@/icons/icon-map.json';

interface LocalIconProps {
  icon: string;
  className?: string;
  style?: React.CSSProperties;
  width?: number | string;
  height?: number | string;
  onClick?: () => void;
}

const LocalIcon: React.FC<LocalIconProps> = ({
  icon,
  className = '',
  style = {},
  width = 24,
  height = 24,
  onClick
}) => {
  const [svgContent, setSvgContent] = useState<string>('');
  const iconPath = iconMap[icon as keyof typeof iconMap];

  useEffect(() => {
    if (!iconPath) {
      console.warn(`Icon not found: ${icon}`);
      return;
    }

    fetch(iconPath)
      .then(response => response.text())
      .then(svg => {
        const modifiedSvg = svg
          .replace(/width="[^"]*"/, `width="${width}"`)
          .replace(/height="[^"]*"/, `height="${height}"`);
        setSvgContent(modifiedSvg);
      })
      .catch(error => {
        console.error(`Failed to load icon: ${icon}`, error);
      });
  }, [icon, iconPath, width, height]);

  if (!iconPath) {
    return null;
  }

  return (
    <span
      className={`inline-flex items-center justify-center ${className}`}
      style={style}
      onClick={onClick}
      onKeyDown={onClick ? (e) => e.key === 'Enter' && onClick() : undefined}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      dangerouslySetInnerHTML={{ __html: svgContent }}
    />
  );
};

export default LocalIcon;