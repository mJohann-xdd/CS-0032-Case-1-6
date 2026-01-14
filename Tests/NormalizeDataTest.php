<?php
use PHPUnit\Framework\TestCase;
require_once __DIR__ . '/../run_clustering.php';

class NormalizeDataTest extends TestCase {

    public function testNormalData() {
        $data = [[1,2],[3,4],[5,6]];
        $result = normalizeData($data);
        $this->assertCount(3, $result);
        $this->assertCount(2, $result[0]);
    }

    public function testZeroStdDeviation() {
        $data = [[2,2],[2,2],[2,2]];
        $result = normalizeData($data);
        foreach ($result as $row) {
            foreach ($row as $value) {
                $this->assertEquals(0, $value);
            }
        }
    }

    public function testNegativeValues() {
        $data = [[-1,-5],[-2,-10],[-3,-15]];
        $result = normalizeData($data);
        $this->assertCount(3, $result);
    }

    public function testEmptyArray() {
        $data = [];
        $result = normalizeData($data);
        $this->assertEmpty($result);
    }
}