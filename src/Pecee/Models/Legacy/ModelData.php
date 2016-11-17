<?php
namespace Pecee\Models\Legacy;

use Pecee\Collection\CollectionItem;

abstract class ModelData extends Model {

    /**
     * @var CollectionItem
     */
	public $data;

	public function __construct() {
		parent::__construct();
		$this->data = new CollectionItem();
	}

	abstract protected function updateData();

	abstract protected function fetchData();

	public function update() {
		$this->updateData();
		return parent::update();
	}

	public function save() {
		parent::save();
		$this->updateData();
	}

	protected function setDataValue($name, $value) {
		$this->data->$name = $value;
	}

	public function setRows(array $rows) {
		parent::setRows($rows);
		$this->fetchData();
	}

	public function setData(array $data) {
		$keys = array_map('strtolower', array_keys($this->getRows()));
		foreach($data as $key => $d) {
			if(!in_array(strtolower($key), $keys)) {
				$this->data->$key = $d;
			}
		}
	}

	public function parseArrayRow($row) {
		return parent::parseArrayRow(array_merge($row, $this->data->getData()));
	}

}