import http from 'k6/http';
import { sleep } from 'k6';

export const options = {
  vus: 50,
  duration: '30s',
};

export default function () {
  http.get(__ENV.URL || 'http://127.0.0.1:8080/health');
  sleep(0.05);
}
