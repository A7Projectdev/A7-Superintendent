export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({
        app: "A7 Superintendent",
        api: "online",
        gmailConnected: false
      });
    }

    return Response.json({
      message: "A7 Superintendent API is running.",
      nextStep: "Set up secure Google Gmail authorization."
    });
  }
};
