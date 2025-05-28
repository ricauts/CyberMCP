# 🔧 CyberMCP Configuration Examples

This directory contains example configuration files for integrating CyberMCP with various AI-powered IDEs and platforms.

## 📁 Configuration Files

### `mcp-config/`

Contains MCP server configuration templates for different IDEs:

- **`claude-desktop.json`** - Claude Desktop configuration
- **`cursor-settings.json`** - Cursor IDE configuration  
- **`windsurf-config.json`** - Windsurf (Codeium) configuration

## 🚀 Quick Setup

1. **Choose your IDE** from the configurations above
2. **Copy the appropriate configuration file** to your IDE's settings directory
3. **Update the file paths** in the configuration to match your system:
   - Replace `/path/to/CyberMCP` with your actual CyberMCP installation path
   - Ensure the path points to the built `dist/index.js` file
4. **Restart your IDE**

## 📖 IDE-Specific Instructions

### Claude Desktop
- **Windows**: Copy content to `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: Copy content to `~/Library/Application Support/Claude/claude_desktop_config.json`  
- **Linux**: Copy content to `~/.config/Claude/claude_desktop_config.json`

### Cursor IDE
- Open Cursor Settings (`Ctrl/Cmd + ,`)
- Add the configuration to your User Settings JSON

### Windsurf (Codeium)
- Open Windsurf Settings
- Add the MCP server configuration to your settings

### VS Code + Cline Extension
- Install the Cline Extension from VS Code marketplace
- Configure Cline Settings with the appropriate MCP server configuration

## ⚠️ Important Notes

- **Build First**: Ensure you've run `npm run build` before using these configurations
- **Path Updates**: Always update the placeholder paths to match your actual installation
- **Restart Required**: Restart your IDE after making configuration changes
- **Test Connection**: Use `npm run test-server` to verify the server works before IDE integration

## 🔗 Additional Resources

- **[Complete Setup Guide](../docs/SETUP_GUIDE.md)** - Detailed step-by-step instructions
- **[Project README](../README.md)** - Main project documentation
- **[MCP Documentation](https://modelcontextprotocol.io/)** - Official MCP protocol docs

---

*Need help? Check the main [README](../README.md) or create an issue on GitHub.* 