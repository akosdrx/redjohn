    let nextRequest = 0;
    let requestQueue = Promise.resolve();
    const spacing = apiKey ? 650 : 6500;
    this.axiosInstance.interceptors.request.use(async config => {
      const reservation = requestQueue.then(async () => {
        const delay = Math.max(0, nextRequest - Date.now());
        if (delay) await new Promise(resolve => setTimeout(resolve, delay));
        nextRequest = Date.now() + spacing;
      });
      requestQueue = reservation.catch(() => {});
      await reservation;
      return config;
    });
