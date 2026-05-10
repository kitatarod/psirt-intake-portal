import sys
import time
import statistics
import tracemalloc
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient
from app.main import app


client = TestClient(app)


def measure_route_performance(path, iterations=30):
    """
    Measure basic local performance for one route:
    - average latency in milliseconds
    - minimum and maximum latency
    - throughput in requests per second
    - success rate based on HTTP 200 responses
    - peak memory footprint during the test
    """
    durations_ms = []
    successful_requests = 0

    tracemalloc.start()
    test_start = time.perf_counter()

    for _ in range(iterations):
        request_start = time.perf_counter()
        response = client.get(path)
        request_end = time.perf_counter()

        duration_ms = (request_end - request_start) * 1000
        durations_ms.append(duration_ms)

        if response.status_code == 200:
            successful_requests += 1

    test_end = time.perf_counter()
    current_memory, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    total_duration_seconds = test_end - test_start

    return {
        "route": path,
        "requests": iterations,
        "success_rate_percent": round((successful_requests / iterations) * 100, 2),
        "average_latency_ms": round(statistics.mean(durations_ms), 2),
        "minimum_latency_ms": round(min(durations_ms), 2),
        "maximum_latency_ms": round(max(durations_ms), 2),
        "throughput_requests_per_second": round(iterations / total_duration_seconds, 2),
        "peak_memory_kb": round(peak_memory / 1024, 2),
    }


def create_svg_chart(results):
    """
    Create a simple SVG bar chart for average route latency.
    This avoids adding extra charting dependencies.
    """
    docs_dir = PROJECT_ROOT / "docs"
    docs_dir.mkdir(exist_ok=True)

    chart_path = docs_dir / "week6_performance_latency_chart.svg"

    max_latency = max(row["average_latency_ms"] for row in results)
    scale = 400 / max_latency if max_latency > 0 else 1

    bars = []
    y = 60

    for row in results:
        label = row["route"]
        latency = row["average_latency_ms"]
        width = latency * scale

        bars.append(
            f'''
            <text x="20" y="{y + 15}" font-size="14">{label}</text>
            <rect x="140" y="{y}" width="{width}" height="25"></rect>
            <text x="{150 + width}" y="{y + 17}" font-size="14">{latency} ms</text>
            '''
        )
        y += 55

    svg = f'''
    <svg width="700" height="220" xmlns="http://www.w3.org/2000/svg">
        <style>
            text {{ font-family: Arial, sans-serif; }}
            rect {{ fill: #4f81bd; }}
        </style>
        <text x="20" y="30" font-size="18" font-weight="bold">
            Week 6 Route Latency Evaluation
        </text>
        {''.join(bars)}
    </svg>
    '''

    chart_path.write_text(svg, encoding="utf-8")
    return chart_path


def main():
    routes_to_test = ["/dashboard", "/metrics"]

    results = [
        measure_route_performance(route, iterations=30)
        for route in routes_to_test
    ]

    print("\nWeek 6 System Performance Evaluation")
    print("=" * 72)
    print(
        f"{'Route':<15}"
        f"{'Requests':<10}"
        f"{'Success %':<12}"
        f"{'Avg Latency':<15}"
        f"{'Throughput':<15}"
        f"{'Peak Memory'}"
    )
    print("-" * 72)

    for row in results:
        print(
            f"{row['route']:<15}"
            f"{row['requests']:<10}"
            f"{row['success_rate_percent']:<12}"
            f"{row['average_latency_ms']} ms".ljust(15)
            f"{row['throughput_requests_per_second']} req/s".ljust(15)
            f"{row['peak_memory_kb']} KB"
        )

    chart_path = create_svg_chart(results)

    print("\nPerformance chart created:")
    print(chart_path)
    print("\nOpen the SVG file in a browser and screenshot it for the report.")


if __name__ == "__main__":
    main()