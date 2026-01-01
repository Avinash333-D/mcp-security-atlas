import asyncio
from mcp.server.fastmcp import FastMCP
import os
from dotenv import load_dotenv
import logging
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.action_chains import ActionChains
from selenium.common.exceptions import TimeoutException, NoSuchElementException
import base64
import json

# Load environment variables
load_dotenv()

app = FastMCP("chrome-mcp-server")

logger = logging.getLogger(__name__)

# Global driver
driver = None

def get_driver():
    global driver
    if driver is None:
        options = Options()
        options.add_argument("--user-agent=Roo-Automated-Security-Researcher-Project")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--remote-debugging-port=9222")
        options.add_argument("--headless")  # Run headless for server
        options.add_experimental_option("useAutomationExtension", False)
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        logger.info("Chrome driver initialized")
    return driver

@app.tool()
async def browser_action(action: str, url: str = "", coordinate: str = "", size: str = "", text: str = "", path: str = "") -> str:
    """Interact with a Chrome browser. Actions: launch, click, hover, type, press, scroll_down, scroll_up, resize, close, screenshot"""
    try:
        drv = get_driver()
        result = {}

        if action == "launch":
            if not url:
                return "Error: URL required for launch"
            drv.get(url)
            logger.info(f"Navigated to {url}")
        elif action == "click":
            if not coordinate:
                return "Error: Coordinate required for click"
            x, y, width, height = map(int, coordinate.replace('@', ',').split(','))
            # Selenium coordinates are absolute, but need to scale if viewport differs
            # For simplicity, assume full screen
            actions = ActionChains(drv)
            actions.move_by_offset(x, y).click().perform()
            logger.info(f"Clicked at {x},{y}")
        elif action == "hover":
            if not coordinate:
                return "Error: Coordinate required for hover"
            x, y, width, height = map(int, coordinate.replace('@', ',').split(','))
            actions = ActionChains(drv)
            actions.move_by_offset(x, y).perform()
            logger.info(f"Hovered at {x},{y}")
        elif action == "type":
            if not text:
                return "Error: Text required for type"
            # Type in active element
            active_element = drv.switch_to.active_element
            active_element.send_keys(text)
            logger.info(f"Typed: {text}")
        elif action == "press":
            if not text:
                return "Error: Key required for press"
            from selenium.webdriver.common.keys import Keys
            key = getattr(Keys, text.upper(), text)
            actions = ActionChains(drv)
            actions.send_keys(key).perform()
            logger.info(f"Pressed: {text}")
        elif action == "scroll_down":
            drv.execute_script("window.scrollBy(0, 500);")
            logger.info("Scrolled down")
        elif action == "scroll_up":
            drv.execute_script("window.scrollBy(0, -500);")
            logger.info("Scrolled up")
        elif action == "resize":
            if not size:
                return "Error: Size required for resize"
            width, height = map(int, size.replace(',', ' ').split())
            drv.set_window_size(width, height)
            logger.info(f"Resized to {width}x{height}")
        elif action == "close":
            drv.quit()
            global driver
            driver = None
            logger.info("Browser closed")
            return "Browser closed"
        elif action == "screenshot":
            if not path:
                return "Error: Path required for screenshot"
            drv.save_screenshot(path)
            logger.info(f"Screenshot saved to {path}")
            # Return base64 encoded image
            with open(path, "rb") as f:
                img_data = base64.b64encode(f.read()).decode()
            result["image"] = f"data:image/png;base64,{img_data}"
        else:
            return f"Unknown action: {action}"

        # After action, take screenshot and get logs
        if action != "close" and action != "screenshot":
            screenshot_path = "/tmp/temp_screenshot.png"  # Temporary path
            drv.save_screenshot(screenshot_path)
            with open(screenshot_path, "rb") as f:
                img_data = base64.b64encode(f.read()).decode()
            result["screenshot"] = f"data:image/png;base64,{img_data}"
            # Console logs - may not work in headless
            try:
                logs = drv.get_log('browser')
                result["console_logs"] = logs
            except:
                result["console_logs"] = []

        return json.dumps(result)
    except Exception as e:
        logger.error(f"Browser action error: {e}")
        return f"Error: {str(e)}"

if __name__ == "__main__":
    app.run()